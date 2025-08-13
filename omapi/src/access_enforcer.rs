// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module defines the [`AccessEnforcer`] type, which implements a GlobalPlatform
//! AcesssControlEnforcer (ACE). It is responsible for enforcing applet access control,
//! restricting which device apps can communicate with which applets.
//!
//! The [`AccessEnforcer`] must communicate with the SE for which it enforces access, to retrieve
//! access rules.  For it to do that, the caller must provide a reference to a [`Terminal`].

use crate::{
    ara::{
        build_rules_from_ara_d_tlv, build_rules_from_ara_m_tlv,
        tlv::{self, Parseable, Tag},
        ApduAccessRule, AppletId, DeviceAppId, Rule, RuleSet,
    },
    system_services::{ClientId, SeSecurityProfile},
    terminal::{ApduResponse, ChannelId, SendSelectOnClose, Terminal},
    utils::{binder_exception, create_exception_status, TraceResultExt},
};
use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement as HwSe;
use binder::{
    ExceptionCode::{ILLEGAL_ARGUMENT, ILLEGAL_STATE, SECURITY, SERVICE_SPECIFIC},
    Result,
};
use log::{debug, error, info, trace};

#[cfg(test)]
mod test;

/// [`CONFIGURABLE_LE`] is the Le value to use in GET_ALL, GET_NEXT and GET_REFRESH_TAG commands.
/// It's available to be customized by OEMs if their device or modem has problems with Le = 0x00.
pub(crate) const CONFIGURABLE_LE: u8 = 0x00;

/// AID of ARA-M applet.
pub const ARA_M_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00];

/// AID of ARA-D applet.
pub const ARA_D_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x44, 0x41, 0x43, 0x00];

// APDU to get the ARA refresh tag.
pub const GET_REFRESH_TAG_APDU: &[u8] = &[0x80, 0xCA, 0xDF, 0x20, CONFIGURABLE_LE];

// APDU to get the ARA rule data.
pub const GET_ALL_APDU: &[u8] = &[0x80, 0xCA, 0xFF, 0x40, CONFIGURABLE_LE];

// APDU to get the next chunk of ARA rule data, in the event the data was too large to be returned
// in the response to the [`GET_ALL`] APDU.
pub const GET_NEXT_APDU: &[u8] = &[0x80, 0xCA, 0xFF, 0x60, CONFIGURABLE_LE];

#[derive(Clone, Copy, Debug)]
enum RuleType {
    AraM,
    AraD,
}

impl RuleType {
    fn aid(&self) -> &'static [u8] {
        match self {
            RuleType::AraM => ARA_M_AID,
            RuleType::AraD => ARA_D_AID,
        }
    }

    fn build_rules(&self, tlv: tlv::Object) -> Result<Vec<Rule>> {
        match self {
            RuleType::AraM => build_rules_from_ara_m_tlv(tlv),
            RuleType::AraD => build_rules_from_ara_d_tlv(tlv),
        }
        .map_err(|e| {
            create_exception_status(
                ILLEGAL_ARGUMENT,
                &format!("Error validating {self:?} rules {e:?}"),
            )
        })
    }
}

#[derive(Clone, Debug)]
struct RuleCache {
    rule_type: RuleType,
    refresh_tag: Option<RefreshTagDo>,
    rules: Vec<Rule>,
}

impl RuleCache {
    fn new(rule_type: RuleType) -> Self {
        RuleCache { rule_type, rules: Vec::new(), refresh_tag: None }
    }

    /// Update cache, reading rules from the SE if the refresh tag has changed.
    fn update(&mut self, terminal: &mut Terminal) -> Result<()> {
        let channel_id = match terminal.open_logical_channel(self.rule_type.aid(), 0x00) {
            Ok(Some(channel_id)) => channel_id,
            Ok(None) => {
                error!("Unable to open SE channel to get {:?} rules.", self.rule_type);
                self.reset();
                return Ok(());
            }
            Err(e)
                if e.exception_code() == SERVICE_SPECIFIC
                    && e.service_specific_error() == HwSe::NO_SUCH_ELEMENT_ERROR =>
            {
                info!("No {:?} applet found.", self.rule_type);
                self.reset();
                return Ok(());
            }
            Err(e) => {
                error!("Unable to open SE channel to get {:?} rules: {e}.", self.rule_type);
                self.reset();
                return Err(e);
            }
        };

        trace!("Opened {channel_id}");
        let result = self.update_in_channel(terminal, channel_id);
        let _ = terminal.close_channel(channel_id, SendSelectOnClose(false));
        result
    }

    fn update_in_channel(&mut self, terminal: &mut Terminal, channel_id: ChannelId) -> Result<()> {
        let se_refresh_tag = read_refresh_tag(terminal, channel_id).trace("Refresh tag").ok();

        if self.refresh_tag.is_some() && se_refresh_tag == self.refresh_tag {
            info!("Refresh tag {se_refresh_tag:?} unchanged. Using cached access rules.");
            return Ok(());
        }

        if se_refresh_tag.is_none() {
            error!("Refresh tag could not be retrieved.")
        } else {
            info!("Refresh tag {:?} changed to {:?}.", self.refresh_tag, se_refresh_tag);
        }

        match read_rule_data(terminal, channel_id, self.rule_type) {
            Ok(rules) => {
                self.rules = rules;
                self.refresh_tag = se_refresh_tag;
                Ok(())
            }
            Err(e) => {
                error!("Error reading ARA rule data: {e}");
                self.reset();
                Err(e)
            }
        }
    }

    /// Reset the cache.
    fn reset(&mut self) {
        self.rules.clear();
        self.refresh_tag = None;
    }
}

#[derive(Clone, Debug)]
pub struct AccessEnforcer {
    rules: RuleSet,
    ara_m_cache: RuleCache,
    ara_d_cache: RuleCache,
    platform_rules: Vec<Rule>,
    security_profile: SeSecurityProfile,
}

impl AccessEnforcer {
    pub fn new(security_profile: SeSecurityProfile, platform_rules: Vec<Rule>) -> Self {
        AccessEnforcer {
            rules: RuleSet::new(platform_rules.iter().cloned()),
            ara_m_cache: RuleCache::new(RuleType::AraM),
            ara_d_cache: RuleCache::new(RuleType::AraD),
            platform_rules,
            security_profile,
        }
    }

    /// Update the cached rules if necessary.  Returns [`Err`] if there was a problem
    /// communicating with the SE.
    ///
    /// Note that even if the rules haven't changed, this function is moderately expensive because
    /// it opens two logical channels and sends APDUs to the SE to get the refresh tags.
    ///
    /// Does nothing if the security profile indicates we're not using ARA.
    pub fn update_rule_cache(&mut self, terminal: &mut Terminal) -> Result<()> {
        if !self.security_profile.use_ara_applet {
            info!("Ignoring ARA rule update request because platform is not using ARA.");
            return Ok(());
        }

        self.ara_m_cache.update(terminal)?;
        self.ara_d_cache.update(terminal)?;
        self.rules = RuleSet::new(
            self.ara_d_cache
                .rules
                .iter()
                .chain(self.ara_m_cache.rules.iter())
                .chain(self.platform_rules.iter())
                .cloned(),
        );

        Ok(())
    }

    /// Clear the rule cache, removing any rules retrieved from the ARA applets and resetting the
    /// refresh tags to force re-reading.
    pub fn reset(&mut self) {
        self.ara_m_cache.reset();
        self.ara_d_cache.reset();
        self.rules = RuleSet::new(self.platform_rules.iter().cloned());
    }

    /// Get APDU access policy for the specified AID, for the current caller.
    pub fn get_policy(&self, aid: &[u8], client_id: &ClientId) -> Result<ApduAccessRule> {
        if self.security_profile.full_access {
            return Ok(ApduAccessRule::Always);
        }

        let app_id = client_id_to_app_id(client_id);
        let applet_id = AppletId::new(aid);

        let policy = self.rules.get_apdu_rule(&app_id, &applet_id);
        if *policy == ApduAccessRule::Never {
            debug!("Access denied for AID {} with caller info {client_id}", hex::encode(aid));
            binder_exception(SECURITY, "APDU access disallowed by policy")
        } else {
            Ok(policy.clone())
        }
    }

    /// Determine if the caller should receive NFC events for the specified [`ClientId`]s.
    pub fn is_nfc_event_allowed(
        &self,
        aid: Option<&[u8]>,
        client_ids: &[ClientId],
    ) -> Result<Vec<bool>> {
        let aid = AppletId::new(aid.unwrap_or_default());
        Ok(client_ids
            .iter()
            .map(|client_id| self.rules.check_nfc(&client_id_to_app_id(client_id), &aid))
            .collect())
    }

    pub fn have_applet_rules(&self) -> bool {
        self.ara_m_cache.refresh_tag.is_some() || self.ara_d_cache.refresh_tag.is_some()
    }
}

/// Convert a [`ClientId`] provided by the system to the [`DeviceAppId`] format required by the
/// ARA rule engine.
fn client_id_to_app_id(caller_id: &ClientId) -> DeviceAppId {
    match caller_id {
        ClientId::PackageInfo(package_infos) => DeviceAppId::new_apk(
            package_infos.iter().flat_map(|info| info.sha256s.iter().cloned()).collect(),
            package_infos.iter().flat_map(|info| info.sha1s.iter().cloned()).collect(),
            package_infos.iter().map(|info| info.package_name.clone()).collect(),
        ),
        ClientId::Uuids(uuids) => DeviceAppId::new_system_component(uuids.clone()),
    }
}

fn read_refresh_tag(terminal: &Terminal, channel_id: ChannelId) -> Result<RefreshTagDo> {
    debug!("Reading ARA refresh tag.");
    let privileged_caller = false;
    let response = terminal.transmit(channel_id, GET_REFRESH_TAG_APDU, privileged_caller)?;
    check_status(&response, "Reading refresh tag")?;
    RefreshTagDo::from_ber(response.risky_data())
}

fn check_status(response: &ApduResponse, context: &str) -> Result<()> {
    if response.successful() {
        Ok(())
    } else {
        binder_exception(
            ILLEGAL_STATE,
            &format!(
                "{context}: Unsuccessful APDU response: {}",
                hex::encode(response.non_zeroizing_status())
            ),
        )
    }
}

fn read_rule_data(
    terminal: &Terminal,
    channel_id: ChannelId,
    rule_type: RuleType,
) -> Result<Vec<Rule>> {
    info!("Reading ARA rules.");
    let privileged_caller = false;
    let mut response = terminal.transmit(channel_id, GET_ALL_APDU, privileged_caller)?;
    check_status(&response, "GET ALL")?;

    let (hdr, data) = tlv::Header::parse(response.risky_data()).map_err(|_| {
        create_exception_status(ILLEGAL_STATE, "Failed to parse ALL-REF-AR-DO header")
    })?;

    // May not have gotten all of the data in one request.
    let additional_data_needed = hdr.len().saturating_sub(data.len());
    let rule_data_needed = response.data_len() + additional_data_needed;

    while response.data_len() < rule_data_needed {
        trace!("Reading additional data, need {}", rule_data_needed - response.data_len());

        let get_next_response = terminal.transmit(channel_id, GET_NEXT_APDU, privileged_caller)?;
        check_status(&get_next_response, "GET NEXT")?;

        trace!("Read {} additional bytes", get_next_response.data_len());
        response.extend(get_next_response);
    }

    trace!("Got ARA rule data: {}", hex::encode(response.risky_data()));
    let (tlv, unused_data) = tlv::parse(response.risky_data()).map_err(|e| {
        create_exception_status(ILLEGAL_ARGUMENT, &format!("Error parsing ARA rule BER: {e:?}"))
    })?;

    if !unused_data.is_empty() {
        error!("Got {} extra bytes of rule data", unused_data.len());
    }
    trace!("Parsed ARA rule TLV objects: {tlv:#?}");

    rule_type.build_rules(tlv)
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct RefreshTagDo([u8; 8]);

impl std::fmt::Debug for RefreshTagDo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RefreshTagDo({})", hex::encode(self.0))
    }
}

impl RefreshTagDo {
    fn from_ber(data: &[u8]) -> Result<Self> {
        let (obj, _) = tlv::parse(data).map_err(|e| {
            create_exception_status(
                ILLEGAL_STATE,
                &format!("Failed to parse RefreshTagDo {}: {e}", hex::encode(data)),
            )
        })?;
        Self::from_tlv(&obj)
    }

    fn from_tlv(tlv_obj: &tlv::Object) -> Result<Self> {
        trace!("RefreshTagDo: {tlv_obj:?}");
        if *tlv_obj.tag() != Tag::ResponseRefreshTagDo {
            return binder_exception(ILLEGAL_STATE, &format!("Got {tlv_obj:?} from GET REFRESH"));
        }

        match tlv_obj.value() {
            tlv::Value::Primitive(data) => (*data)
                .try_into()
                .map(Self)
                .map_err(|_| create_exception_status(ILLEGAL_STATE, "Invalid")),
            _ => binder_exception(
                ILLEGAL_STATE,
                &format!("Invalid content {} in ResponseRefreshTagDo", tlv_obj.value()),
            ),
        }
    }
}
