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

//! Implementation of the rules engine of a Global Platform Access Control Enforcer.  See
//!
//! https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf
//!
//! and
//!
//! https://globalplatform.org/wp-content/uploads/2018/06/GPD_Device_API_Access_Control_v1.0_PublicRelease.pdf
//!
//! The comments in this file reference those documents as ARA-M and ARA-D, respectively.
//!
//! Parse errors are reported as strings, generally using [`anyhow::bail`], because it's expected
//! that the only useful thing that can be done with errors is to log them so humans can examine
//! and repair the rules.

use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};
use std::{array::TryFromSliceError, cmp::Ordering};

use anyhow::{anyhow, bail, ensure, Context, Result};
use itertools::{izip, Itertools};
use log::{info, trace};

use super::tlv;
use super::xml;

#[cfg(test)]
mod test;

pub const SHA1_OR_UUID_LEN: usize = 20;
pub const SHA256_LEN: usize = 32;
pub const APDU_HEADER_LEN: usize = 4;
/// An APDU filter set consists of two byte arrays the same length as an APDU header.  One is a
/// mask that is bitwise ANDed with the header and the other is a pattern that is compared with
/// the mask result.
pub const APDU_FILTER_SET_LEN: usize = 2 * APDU_HEADER_LEN;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sha256Digest(pub [u8; SHA256_LEN]);

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sha1DigestOrUuid(pub [u8; SHA1_OR_UUID_LEN]);

/// [`DeviceAppId`] identifes the client that wishes to use the Secure element.  Clients may be
/// APKs, which are identified by their certificate hashes (SHA-256 or SHA-1) and, optionally,
/// package names, or they may be system components, which are identified by a UUID.
///
/// Note that [`DeviceAppId`] is filled out by the system when it identifies the caller.  Compare
/// to [`DeviceAppIdRef`] and [`DeviceAppPkgRef`], the ARA rule structures that are matched
/// against [`DeviceAppId`].
#[derive(PartialEq)]
pub enum DeviceAppId {
    Apk {
        /// SHA-256 hashes of all of the APK's signing certificates.
        sha256s: Vec<Sha256Digest>,
        /// SHA-1 hashes of all of the APK's signing certificates.
        sha1s: Vec<Sha1DigestOrUuid>,
        /// APK package names.  Note that although a client has a single package name, shared UIDs
        /// make it impossible to identify which package is the caller, so all are checked.
        package_names: Vec<String>,
    },
    SystemComponent {
        /// UUIDs of the system component.  Components should probably have only one UUID, but the
        /// UUID mapping file format does not prevent mapping a uid to multiple UUIDs, so we allow
        /// for more than one.
        uuids: Vec<Sha1DigestOrUuid>,
    },
}

impl DeviceAppId {
    /// Construct a [`DeviceAppId`] for an APK with the provided hashes, UUIDs and package names.
    pub fn new_apk(
        sha256s: Vec<Sha256Digest>,
        sha1s: Vec<Sha1DigestOrUuid>,
        package_names: Vec<String>,
    ) -> Self {
        DeviceAppId::Apk { sha256s, sha1s, package_names }
    }

    /// Construct a [`DeviceAppId`] for a system component with the provided UUIDs.
    pub fn new_system_component(uuids: Vec<Sha1DigestOrUuid>) -> Self {
        DeviceAppId::SystemComponent { uuids }
    }
}

impl std::fmt::Debug for DeviceAppId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceAppId::Apk { sha256s, sha1s, package_names } => {
                write!(
                formatter,
                "DeviceAppId: Apk {{ Sha1CertHashes: [{}], Sha256CertHashes [{}], PackageNames [{}] }} ",
                sha1s.iter().map(hex::encode).join(", "),
                sha256s.iter().map(hex::encode).join(", "),
                package_names.iter().join(", "),
            )
            }
            DeviceAppId::SystemComponent { uuids } => {
                write!(
                    formatter,
                    "DeviceAppId: SystemComponent: {{ UUIDs: [{}] }}",
                    uuids.iter().map(hex::encode).join(", "),
                )
            }
        }
    }
}

/// AppletId identifies a target applet, either by AID (applet ID) or by specifying the SE
/// channel's default.
///
/// Note that the library doesn't know which applet is default, it just determines whether the
/// rules allow whichever applet is the default (the one implicitly selected by opening a channel
/// to the applet without specifying an AID) to be accessed by the specified app.
#[derive(Debug, PartialEq, Clone)]
pub enum AppletId<'a> {
    /// Specifies an applet by AID; references the bytes of the AID value.
    Aid(&'a [u8]),
    /// Specifies that the default-selected applet is being used.
    DefaultApplet,
}

impl<'a> AppletId<'a> {
    pub fn new(aid: &'a [u8]) -> Self {
        if aid.is_empty() {
            AppletId::DefaultApplet
        } else {
            AppletId::Aid(aid)
        }
    }
}

/// ARA rules are ranked by specificity, and are evaluated strictly in the order defined by this
/// enum, "Carrier" first.  The reason for the naming is that "Least" to "Highest" are the
/// priorities defined in the first ARA-M document, and "Carrier" represents the even higher,
/// carrier-only priority level defined by ARA-D.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RuleSpecificity {
    /// Specifies device app & package name
    Carrier,
    /// Specifies AID and device app
    Highest,
    /// Specifies AID, matches any device app
    High,
    /// Matches any AID, specifies device app
    Low,
    /// Matches any AID and any device app
    Least,
}

/// Collection of ARA rules, which can be queried to check access permissionss.
///
/// Corresponds to Response-ALL-REF-DO.  See ARA-M page 35.
#[derive(Debug, Clone)]
pub struct RuleCache {
    /// ARA rules to be applied.  Will be checked in the order they're found in the vector, which
    /// means they must be ordered correctly when the [`RuleCache`] is created.
    rules: Vec<Rule>,
}

impl RuleCache {
    /// This method constructs a [`RuleCache`] from an iterator over [`Rule`]s, but it does some
    /// extra work to implement meta-rules that would be applied at evaluation time, i.e.  when
    /// trying to compute access for an AID and app.  By doing some extra work now we can
    /// pre-compute the result of the meta-rules so the work doesn't have to be done during
    /// evaluation. We do the following:
    ///
    /// 1.  Access merging.  The specification requires that if multiple rules match a request,
    ///     the strictest of their access specifications win.  But because of the hierarchical way
    ///     the rules are evaluated, the only way two (or more) rules can match a request is if
    ///     they have the same match criteria, i.e. specify the same AID and App.  We handle this
    ///     by finding such redundant rules and pre-merging them.  The result is that there is
    ///     only one rule for any match criteria pair (AID and app).
    ///
    /// 2.  AID shadowing.  The specification requires that if an app-wildcard rule (specific AID,
    ///     but any app) matches a request, but there is some fully-specific rule (specifies AID
    ///     and app) that references the same AID but a different app, the engine should deny the
    ///     request.  We handle this by finding any app-wildcard rules that are "shadowed" by
    ///     specific rules and setting their access to NEVER.
    ///
    /// 3.  App shadowing.  The specification requires that if a fully generic rule (any AID, any
    ///     app) matches a request, but there exists an AID wildcard rule (any AID, specific app)
    ///     that matches a different app, the engine must return NEVER, which is the same thing it
    ///     returns if no rules match.  Therefore, if there are any AID wildcard rules, we discard
    ///     any fully-generic rules.
    ///
    /// 4.  Priority hierarchy.  Rules must be applied in strict priority order (based on
    ///     specificity/genericity).  We handle this by sorting the rules by
    ///     [`MatchCriteria::cmp`], which is defined to produce the correct order.  Sorting is
    ///     provided by the [`BTreeMap`].
    ///
    /// By applying these optimizations now, we don't have to bother with these meta-rules at
    /// evaluation time.  We can just apply the rules sequentially, taking the first match.
    pub fn new<I>(rules_iter: I) -> Self
    where
        I: IntoIterator<Item = Rule>,
    {
        let mut rules = construct_merged_rule_map(rules_iter);
        handle_aid_shadowing_rule(&mut rules);
        handle_app_shadowing(&mut rules);
        RuleCache { rules: rules.into_iter().map(Rule::from_tuple).collect() }
    }

    /// Convert parsed-TLV object containing rules to a [`Vec<Rule>`], preparatory to creating a
    /// [`RuleCache`] (perhaps containing rules from multiple sources).
    pub fn tlv_to_rules(tlv: tlv::Object) -> Result<Vec<Rule>> {
        ensure!(*tlv.tag() == tlv::Tag::ResponseAllRefArDo);
        let value = tlv.get_content();
        match value {
            tlv::Value::Empty => Ok(Vec::new()),
            tlv::Value::Constructed(vec) => {
                vec.into_iter().filter(is_known_tag).map(Rule::from_tlv).collect()
            }
            tlv::Value::Primitive(_) => {
                bail!("Invalid RuleCache content {}", value)
            }
        }
    }

    /// Convert parsed-XML object containing rules to a [`Vec<Rule>`], preparatory to creating a
    /// [`RuleCache`] (perhaps containing rules from multiple sources).
    pub fn xml_to_rules(xml: xml::Rules) -> Result<Vec<Rule>> {
        xml.ref_ar_do.into_iter().map(Rule::from_xml).collect()
    }

    /// Returns the APDU access restrictions for the specified device app and AID.  To check the
    /// default-selected applet specify [`AppletId::DefaultApplet`] for `aid`.
    pub fn get_apdu_rule(&self, app: &DeviceAppId, aid: &AppletId) -> &ApduAccessRule {
        trace!("Checking APDU access to {aid:02x?} for {app:?}");
        &self.get_rules(app, aid).apdu
    }

    /// Check whether the specified app should be notified about NFC events related to the
    /// specified applet.  To check the default-selected applet specify
    /// [`AppletId::DefaultApplet`] for `aid`.
    pub fn check_nfc(&self, app: &DeviceAppId, aid: &AppletId) -> bool {
        trace!("Checking NFC access to {aid:02x?} for {app:?}");
        self.get_rules(app, aid).nfc == NfcAccessRule::Always
    }

    /// Returns the access rules, both APDU and NFC, for the specified device app and AID.  To
    /// check the default-selected applet specify [`AppletId::DefaultApplet`] for `applet`.
    fn get_rules(&self, app: &DeviceAppId, aid: &AppletId) -> &AccessRules {
        self.rules
            .iter()
            .find_map(|rule| rule.criteria.matches(app, aid).then_some(&rule.access))
            .unwrap_or(&AccessRules::NEVER)
    }

    #[cfg(test)]
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        Ok(Self::new(Self::tlv_to_rules(tlv)?))
    }

    #[cfg(test)]
    fn check_apdu(&self, app: &DeviceAppId, aid: &AppletId, apdu_header: &ApduHeader) -> bool {
        self.get_apdu_rule(app, aid).allow_apdu(apdu_header)
    }
}

/// Merge rules from an iterator into a map.  "Merge" means that where two [`Rule`]s have the same
/// [`MatchCriteria`], their [`AccessRules`]s are merged.
fn construct_merged_rule_map<I>(rules: I) -> BTreeMap<MatchCriteria, AccessRules>
where
    I: IntoIterator<Item = Rule>,
{
    let mut map = BTreeMap::new();
    for rule in rules {
        match map.entry(rule.criteria) {
            Entry::Vacant(entry) => {
                entry.insert(rule.access);
            }
            Entry::Occupied(mut entry) => entry.get_mut().merge(rule.access),
        }
    }
    map
}

/// Handle AID shadowing by setting [`AccessRules::NEVER`] for any app-wildcard rule (i.e.
/// [`RuleSpecificity::High`]) with an AID that is mentioned in a fully-specified (i.e.
/// [`RuleSpecificity::Highest`] rule.
fn handle_aid_shadowing_rule(rules: &mut BTreeMap<MatchCriteria, AccessRules>) {
    let mut shadowing_aids = BTreeSet::new();
    for (criteria, _) in rules.iter() {
        if criteria.specificity() == RuleSpecificity::Highest {
            shadowing_aids.insert(criteria.aid_ref.clone());
        }
    }

    for (criteria, access) in rules.iter_mut() {
        if criteria.specificity() == RuleSpecificity::High
            && shadowing_aids.contains(&criteria.aid_ref)
        {
            *access = AccessRules::NEVER;
        }
    }
}

/// Handle app shadowing by removing any fully-generic rules ([`RuleSpecificity::Least`]) if any
/// AID-wildcard ([`RuleSpecificity::Low`]) rules exist.
///
/// We search in reverse order because [`Iterator::any`] short-circuits and
/// [`RuleSpecificity::Low`] rules are towards the end of the rule set. Minor efficiency tweak.
fn handle_app_shadowing(rules: &mut BTreeMap<MatchCriteria, AccessRules>) {
    if rules.iter().rev().any(|(criteria, _)| criteria.specificity() == RuleSpecificity::Low) {
        rules.retain(|criteria, _| criteria.specificity() != RuleSpecificity::Least);
    };
}

/// An access rule, specifying the conditions of match and the access permissions/restrictions to
/// be applied.
///
/// Corresponds to REF-AR-DO.  See ARA-M page 68.
#[derive(Debug, Clone)]
pub struct Rule {
    criteria: MatchCriteria,
    access: AccessRules,
}

impl Rule {
    fn from_tuple(tuple: (MatchCriteria, AccessRules)) -> Self {
        let (criteria, access) = tuple;
        Self { criteria, access }
    }

    /// Create a [`Rule`] from a [`tlv::Object`].  Returns [`Err`] if the object does not contain
    /// a valid REF-AR-DO structure.
    fn from_tlv(tlv: tlv::Object) -> Result<Rule> {
        ensure!(*tlv.tag() == tlv::Tag::RefArDo);
        let value = tlv.get_content();
        let tlv::Value::Constructed(vec) = value else {
            bail!("Invalid RefArDo content {}", value);
        };
        Self::from_tlv_vec(vec).context("Parsing RefArDo")
    }

    /// Create a [`Rule`] from an [`xml::RefArDo`].  Returns [`Err`] if the object does not
    /// contain a valid REF-AR-DO structure.
    fn from_xml(ref_ar_do: xml::RefArDo) -> Result<Rule> {
        let criteria = MatchCriteria::from_xml(ref_ar_do.get_match_criteria())?;
        let access = AccessRules::from_xml(ref_ar_do.get_apdu_access())?;
        Ok(Rule { criteria, access })
    }

    /// Create a [`Rule`] from a vector containing a REF-DO and AR-DO [`tlv::Object`]s.  Returns
    /// [`Err`] if the objects are not well-formed.
    fn from_tlv_vec(vec: Vec<tlv::Object<'_>>) -> Result<Rule> {
        let mut access = None;
        let mut criteria = None;

        for tlv in vec.into_iter().filter(is_known_tag) {
            match tlv.tag() {
                tlv::Tag::RefDo => {
                    ensure!(access.is_none(), "Found ArDo before RefDo");
                    ensure!(criteria.is_none(), "Found multiple RefDo");
                    criteria = Some(MatchCriteria::from_tlv(tlv).context("Parsing RefDo")?);
                }
                tlv::Tag::ArDo => {
                    ensure!(access.is_none(), "Found multiple ArDo");
                    access = Some(AccessRules::from_tlv(tlv).context("Parsing ArDo")?);
                }
                tag => bail!("Invalid tag {:?}", tag),
            }
        }

        let criteria = criteria.ok_or_else(|| anyhow!("Missing RefDo"))?;
        let access = access.ok_or_else(|| anyhow!("Missing ArDo"))?;

        Ok(Rule { criteria, access })
    }
}

/// Defines the conditions for access.
///
/// The order in which rules are applied depends on their match criteria.  This type implements
/// [`Ord`] so sorted rules are in the order the specification requires them to be evaluated.
///
/// Corresponds to REF-DO.  See ARA-M page 68 and page ARA-D page 41.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MatchCriteria {
    aid_ref: AppletRef,
    hash_ref: DeviceAppIdRef,
    pkg_ref: Option<DeviceAppPkgRef>,
}

impl MatchCriteria {
    /// Create [`MatchCriteria`] from [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::RefDo);
        match tlv.get_content() {
            tlv::Value::Constructed(vec) => Self::from_tlv_vec(vec),
            other => bail!("Invalid RefDo content {}", other),
        }
    }

    /// Create [`MatchCriteria`] from [`xml::RefDo`].
    fn from_xml(ref_do: &xml::RefDo) -> Result<MatchCriteria> {
        Ok(MatchCriteria {
            aid_ref: AppletRef::from_xml(ref_do.get_aid_ref())?,
            hash_ref: DeviceAppIdRef::from_xml(ref_do.get_app_id())?,
            pkg_ref: None,
        })
    }

    /// Create [`MatchCriteria`] from a vector containing one of:
    ///
    /// 1. AID-REF-DO || DeviceAppID-REF-DO
    /// 2. DeviceAppID-REF-DO
    /// 3. DeviceAppID-REF-DO || PKG-REF-DO
    ///
    /// (|| represents concatenation).
    ///
    /// Case 1 represents an ARA-M  rule.  Cases 2 and 3 are ARA-D rules and apply to all applets;
    /// carriers apps have "device" access, i.e. access to the entire SE (though the SE will apply
    /// its own security constraints).  This means that if we don't find an AID-REF-DO, we set
    /// [`MatchCriteria::aid_ref`] to [`AppletRef::Carrier`].
    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self> {
        ensure!(!vec.is_empty(), "Found empty REF-DO");

        let mut pkg_ref = None;
        let mut hash_ref = None;
        let mut aid_ref = AppletRef::Carrier;

        for (pos, entry) in vec.into_iter().filter(is_known_tag).enumerate() {
            ensure!(pos < 2, "Found {} components in REF-DO", pos + 1);
            match entry.tag() {
                tlv::Tag::DeviceAppIdRefDo => {
                    hash_ref = {
                        ensure!(hash_ref.is_none());
                        Some(DeviceAppIdRef::from_tlv(entry)?)
                    }
                }
                tlv::Tag::PkgRefDo => {
                    ensure!(pos == 1, "PKG-REF-DO found in position {pos}");
                    ensure!(hash_ref.is_some(), "PKG-REF-DO not preceded by DeviceAppID-REF-DO");
                    pkg_ref = Some(DeviceAppPkgRef::from_tlv(entry)?)
                }
                tlv::Tag::AidRefDoSpecificApplet | tlv::Tag::AidRefDoImplicit => {
                    ensure!(pos == 0, "AID-REF-DO found in position {pos}");
                    aid_ref = AppletRef::from_tlv(entry)?
                }
                _ => bail!("Invalid tag {} in REF-DO", entry.tag()),
            }
        }

        Ok(Self {
            aid_ref,
            hash_ref: hash_ref.ok_or_else(|| anyhow!("No DeviceAppId-REF-DO in REF-DO"))?,
            pkg_ref,
        })
    }

    /// Returns true iff these MatchCriteria match the supplied app ID and applet ID.
    fn matches(&self, app_id: &DeviceAppId, aid: &AppletId) -> bool {
        self.aid_ref.matches(aid)
            && self.hash_ref.matches(app_id)
            && self.pkg_ref.as_ref().map_or(true, |p| p.matches(app_id))
    }

    /// Calculate the specificity-derived priority of a rule from the booleans indicating whether
    /// the rule specifies a specific AID and/or [`super::DeviceAppId`].  See the priority table
    /// on ARA-M page 27.
    fn specificity(&self) -> RuleSpecificity {
        if self.aid_ref == AppletRef::Carrier {
            return RuleSpecificity::Carrier;
        }

        let explicit_aid = self.aid_ref != AppletRef::AllApplets;
        let explicit_app = self.hash_ref != DeviceAppIdRef::AllApplications;
        match (explicit_aid, explicit_app) {
            (true, true) => RuleSpecificity::Highest,
            (true, false) => RuleSpecificity::High,
            (false, true) => RuleSpecificity::Low,
            (false, false) => RuleSpecificity::Least,
        }
    }
}

impl PartialOrd for MatchCriteria {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MatchCriteria {
    fn cmp(&self, other: &Self) -> Ordering {
        self.specificity()
            .cmp(&other.specificity())
            .then(self.hash_ref.cmp(&other.hash_ref))
            .then(self.pkg_ref.cmp(&other.pkg_ref))
            .then(self.aid_ref.cmp(&other.aid_ref))
    }
}

/// Defines the AID matching condition for a [`Rule`].
///
/// Mostly corresponds to AID-REF-DO.  See ARA-M page 66.
///
/// The "Carrier" variant is needed for ARA-D integration.  It is used in the case of an ARA-D
/// rule which doesn't specify AID because carriers have access to all applets.  In that sense
/// it's similar to the "AllApplets" wildcard case, except that Carrier rules are higher in
/// priority and not subject to shadowing rules.
#[derive(PartialEq, Clone, Eq, PartialOrd, Ord)]
enum AppletRef {
    AllApplets,
    DefaultApplet,
    SpecificApplet(Vec<u8>),
    Carrier,
}

impl AppletRef {
    /// Create a new instance from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        match tlv.tag() {
            tlv::Tag::AidRefDoSpecificApplet => match tlv.value() {
                tlv::Value::Empty => Ok(Self::AllApplets),
                tlv::Value::Primitive(bytes) => Ok(Self::SpecificApplet(bytes.to_vec())),
                tlv::Value::Constructed(_) => bail!("Found invalid content in AidRefDo"),
            },
            tlv::Tag::AidRefDoImplicit => match tlv.value() {
                tlv::Value::Empty => Ok(Self::DefaultApplet),
                _ => {
                    bail!("Unexpected content {} in AidRefDoImplicit", tlv.value());
                }
            },
            other => bail!("Found unexpected {other:?}, where AidRefDo expected."),
        }
    }

    /// Create a new instance from an [`xml::AidRefDo`].
    fn from_xml(aid_ref_do: &xml::AidRefDo) -> Result<Self> {
        let aid = aid_ref_do.get_aid();
        let aid_ref = match aid.len() {
            0 => Self::AllApplets,
            _ => Self::SpecificApplet(aid.to_vec()),
        };
        Ok(aid_ref)
    }

    /// Returns true iff the supplied [`AppletId`] matches [`self`]`.
    fn matches(&self, applet_id: &AppletId) -> bool {
        match self {
            AppletRef::AllApplets | AppletRef::Carrier => true,
            AppletRef::DefaultApplet => *applet_id == AppletId::DefaultApplet,
            AppletRef::SpecificApplet(aid) => *applet_id == AppletId::Aid(aid),
        }
    }
}

impl std::fmt::Debug for AppletRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Carrier => write!(f, "Carrier"),
            Self::AllApplets => write!(f, "AllApplets"),
            Self::DefaultApplet => write!(f, "DefaultApplet"),
            Self::SpecificApplet(arg0) => write!(f, "SpecificApplet({})", hex::encode(arg0)),
        }
    }
}

/// Defines the device app ID matching condition for a [`Rule`].
///
/// Corresponds to DeviceAppID-REF-DO.  See ARA-M page 67 and ARA-D page 40.
///
/// The reason we have a "Sha1OrUuid" variant, rather than two separate variants for SHA-1 and
/// UUID values is because it is impossible to distinguish which of those is meant by a 20-byte
/// value in the encoded rule.
///
/// Note that the order of the first two variants is important.  Rules are ordered by
/// MatchCriteria, which are ordered first by priority, then by DeviceAppIdRef, specifically to
/// ensure that SHA-256 IDs are tested before SHA1/UUID IDs, so [`DeviceAppIdRef::Sha256`]
/// instances must be less than (come before in sorting order) [`DeviceAppIdRef::Sha1OrUuid`]
/// instances.  The relative position of [`DeviceAppIdRef::AllApplications`] instances doesn't
/// matter.
#[derive(PartialEq, Clone, Eq, PartialOrd, Ord, Debug)]
enum DeviceAppIdRef {
    Sha256(Sha256Digest),
    Sha1OrUuid(Sha1DigestOrUuid),
    AllApplications,
}

impl DeviceAppIdRef {
    /// Create a new instance from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::DeviceAppIdRefDo);

        let app_id_ref = match tlv.value() {
            tlv::Value::Empty => Self::AllApplications,
            tlv::Value::Primitive(data) => match data.len() {
                SHA1_OR_UUID_LEN => Self::Sha1OrUuid((*data).try_into()?),
                SHA256_LEN => Self::Sha256((*data).try_into()?),
                _ => bail!("Invalid DeviceAppId content length"),
            },
            tlv::Value::Constructed(_) => {
                bail!("Invalid content {} found in DeviceAppIdRefDo", tlv.value())
            }
        };

        Ok(app_id_ref)
    }

    /// Create a new instance from a [`xml::DeviceAppIdRefDo`].
    fn from_xml(deviceappid_ref_do: &xml::DeviceAppIdRefDo) -> Result<Self> {
        let bytes = deviceappid_ref_do.get_app_id();
        match bytes.len() {
            0 => Ok(Self::AllApplications),
            SHA1_OR_UUID_LEN => Ok(Self::Sha1OrUuid(bytes.try_into()?)),
            SHA256_LEN => Ok(Self::Sha256(bytes.try_into()?)),
            _ => unreachable!(),
        }
    }

    /// Returns true iff the supplied [`DeviceAppId`] matches self.
    fn matches(&self, app_id: &DeviceAppId) -> bool {
        match app_id {
            DeviceAppId::Apk { sha256s, sha1s, package_names: _ } => match self {
                DeviceAppIdRef::Sha256(sha256) => sha256s.iter().contains(&sha256),
                DeviceAppIdRef::Sha1OrUuid(sha1) => sha1s.iter().contains(&sha1),
                DeviceAppIdRef::AllApplications => true,
            },
            DeviceAppId::SystemComponent { uuids } => match self {
                DeviceAppIdRef::Sha256(_) => false,
                DeviceAppIdRef::Sha1OrUuid(uuid) => uuids.iter().contains(&uuid),
                DeviceAppIdRef::AllApplications => true,
            },
        }
    }
}

/// Defines an app ID matching condition based on package name.
///
/// This is an ARA-D feature, not an ARA-M feature. See ARA-D page 41.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceAppPkgRef(String);

impl DeviceAppPkgRef {
    /// Create a new instance from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::PkgRefDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Ok(DeviceAppPkgRef(ascii_bytes_to_string(data)?)),
            value => bail!("Invalid content {} found in PkgRefDo", value),
        }
    }

    fn matches(&self, app_id: &DeviceAppId) -> bool {
        match app_id {
            DeviceAppId::Apk { sha1s: _, sha256s: _, package_names } => {
                package_names.iter().any(|p| *p == self.0)
            }
            DeviceAppId::SystemComponent { uuids: _ } => false,
        }
    }
}

fn ascii_bytes_to_string(bytes: &[u8]) -> Result<String> {
    if let Ok(utf8_str) = std::str::from_utf8(bytes) {
        if utf8_str.is_ascii() {
            return Ok(utf8_str.to_owned());
        }
    }
    bail!("Non-ASCII content in bytes.")
}

/// Defines the conditions for access.
///
/// Corresponds to AR-DO, see ARA-M page 69.
#[derive(Debug, Clone)]
pub struct AccessRules {
    apdu: ApduAccessRule,
    nfc: NfcAccessRule,
}

impl AccessRules {
    // It's convenient to have a static [`NEVER`] rule, so we can return references to it.
    const NEVER: AccessRules =
        AccessRules { apdu: ApduAccessRule::Never, nfc: NfcAccessRule::Never };

    /// Create [`AccessRules`] from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::ArDo);
        match tlv.get_content() {
            tlv::Value::Constructed(vec) => Self::from_tlv_vec(vec),
            content => bail!("Invalid content {content} in ArDo"),
        }
    }

    /// Create [`AccessRules`] from a vector of APDU-AR-DO and NFC-AR-DO objects.
    fn from_tlv_vec(obj_vec: Vec<tlv::Object<'_>>) -> Result<Self> {
        let mut apdu = None;
        let mut nfc = None;

        for object in obj_vec.into_iter().filter(is_known_tag) {
            match object.tag() {
                tlv::Tag::ApduArDo => {
                    ensure!(apdu.is_none(), "Found multiple ApduArDo instances in ArDo");
                    ensure!(nfc.is_none(), "Found ApduArDo instance after NfcArDo");
                    apdu =
                        Some(ApduAccessRule::from_tlv(object).context("Invalid ApduArDo in ArDo")?)
                }
                tlv::Tag::NfcArDo => {
                    ensure!(nfc.is_none(), "Found multiple NfcArDo instances in ArDo");
                    nfc = Some(NfcAccessRule::from_tlv(object).context("Invalid NfcArDo in ArDo")?)
                }
                _ => bail!("Invalid tag {} in ArDo content", object.tag()),
            }
        }

        let (apdu, nfc) = handle_partial_ardo(apdu, nfc)?;
        Ok(AccessRules { apdu, nfc })
    }

    fn from_xml(ar_do: &xml::ArDo) -> Result<Self> {
        let apdu = ApduAccessRule::from_data(ar_do.get_apdu_access())?;
        let (apdu, nfc) = handle_partial_ardo(Some(apdu), None)?;
        Ok(AccessRules { apdu, nfc })
    }
    fn merge(&mut self, other: Self) {
        self.apdu.merge(other.apdu);
        self.nfc.merge(other.nfc);
    }
}

fn handle_partial_ardo(
    apdu: Option<ApduAccessRule>,
    nfc: Option<NfcAccessRule>,
) -> Result<(ApduAccessRule, NfcAccessRule)> {
    // This translation table implements the logic described in ARA-M Annex G, page 128.  It
    // handles the cases where one of APDU/NFC is not present in the rule.
    let (apdu, nfc) = match (apdu, nfc) {
        (Some(apdu), Some(nfc)) => (apdu, nfc),
        (Some(ApduAccessRule::Never), None) => (ApduAccessRule::Never, NfcAccessRule::Never),
        (Some(apdu), None) => (apdu, NfcAccessRule::Always),
        (None, Some(nfc)) => (ApduAccessRule::Never, nfc),
        (None, None) => bail!("Empty ArDo."),
    };
    Ok((apdu, nfc))
}

pub struct ApduHeader([u8; APDU_HEADER_LEN]);

impl From<[u8; 4]> for ApduHeader {
    fn from(array: [u8; 4]) -> Self {
        ApduHeader(array)
    }
}

/// Defines access permissions for APDU access.
///
/// Corresponds to APDU-AR-DO (pg. 70).
#[derive(PartialEq, Debug, Clone)]
pub enum ApduAccessRule {
    /// APDU access is always allowed.
    Always,
    /// APDU access is allowed only if it matches one of the APDU filters.
    PartialAllow(ApduFilterSet),
    /// APDU access is never allowed.
    Never,
}

impl ApduAccessRule {
    /// Returns true if the specified APDU meets the access criteria.
    pub fn allow_apdu(&self, apdu_header: &ApduHeader) -> bool {
        match self {
            ApduAccessRule::Always => true,
            ApduAccessRule::Never => false,
            ApduAccessRule::PartialAllow(filter_set) => filter_set.allow(apdu_header),
        }
    }

    /// Create a new instance from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::ApduArDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Self::from_data(data),
            _ => bail!("Invalid content {} in ApduArDo", tlv.value()),
        }
    }

    /// Create [`ApduAccessRule`] from a buffer containing the content of an APDU-AR-DO object.
    fn from_data(data: &[u8]) -> Result<Self> {
        Ok(match data.len() {
            1 => match data[0] {
                0 => Self::Never,
                1 => Self::Always,
                _ => bail!("Invalid data byte {} in ApduArDo", data[0]),
            },
            0 => bail!("No data in ApduArDo"),
            _ => Self::PartialAllow(
                ApduFilterSet::from_data(data).context("Invalid ApduFilters in ApduArDo")?,
            ),
        })
    }

    /// Merge other into self, always taking the stricter rule.
    fn merge(&mut self, other: Self) {
        // Take ownership of the contents of `self`.
        let mut this = ApduAccessRule::Always;
        std::mem::swap(self, &mut this);

        *self = match this {
            ApduAccessRule::Never => ApduAccessRule::Never,
            ApduAccessRule::Always => other,
            ApduAccessRule::PartialAllow(mut this_set) => match other {
                ApduAccessRule::Never => ApduAccessRule::Never,
                ApduAccessRule::Always => ApduAccessRule::PartialAllow(this_set),
                ApduAccessRule::PartialAllow(mut other_set) => {
                    this_set.0.append(&mut other_set.0);
                    this_set.0.sort_unstable();
                    this_set.0.dedup();
                    ApduAccessRule::PartialAllow(this_set)
                }
            },
        };
    }
}

/// Defines the set of allowed APDUs.  Call [`ApduFilterSet::allow`] to determine whether
/// a given APDU should be permitted.
#[derive(PartialEq, Debug, Clone)]
pub struct ApduFilterSet(Vec<ApduFilter>);

impl ApduFilterSet {
    /// Create new ApduFilterSet from provided data.  Will return Err if data buffer is empty or
    /// not a multiple of 8 bytes in length.
    fn from_data(data: &[u8]) -> Result<Self> {
        ensure!(
            !data.is_empty() && data.len() % APDU_FILTER_SET_LEN == 0,
            "Invalid data in ApduFilterSet {data:?}"
        );
        let mut filters: Vec<ApduFilter> =
            data.chunks_exact(APDU_FILTER_SET_LEN).map(ApduFilter::from_data).collect();
        filters.sort_unstable(); // Ensure that filter sets with the same contents compare Equal.
        Ok(ApduFilterSet(filters))
    }

    /// Returns true if the specified APDU header meets the filter requirements and should be
    /// allowed to be sent to the SE.
    fn allow(&self, apdu_header: &ApduHeader) -> bool {
        self.0.iter().any(|filter| filter.allow_apdu(apdu_header))
    }
}

/// Defines a set of allowed APDUs.
///
/// Each of [`ApduFilter::allowed`] and [`ApduFilter::mask`] are four bytes, corresponding to the
/// CLA, INS, P1 and P2 bytes of an APDU.  [`ApduFilter::mask`] is bitwise ANDed with the APDU to
/// be tested and the result is compared with [`ApduFilter::allowed`].  If they match, the APDU is
/// allowed.
///
/// See definition of APDU-AR-DO (pg. 70).
#[derive(PartialEq, Clone, PartialOrd, Ord, Eq)]
struct ApduFilter {
    allowed: [u8; APDU_HEADER_LEN],
    mask: [u8; APDU_HEADER_LEN],
}

impl ApduFilter {
    /// Create new ApduFilter from provided data.  Will panic if data buffer is not 8 bytes.
    fn from_data(data: &[u8]) -> ApduFilter {
        let data: &[u8; APDU_FILTER_SET_LEN] =
            data.try_into().expect("ApduFilter called with incorrect data length");
        ApduFilter {
            allowed: data[..APDU_HEADER_LEN].try_into().unwrap(),
            mask: data[APDU_HEADER_LEN..].try_into().unwrap(),
        }
    }

    /// Return true if the provided APDU header is allowed according to this rule.
    fn allow_apdu(&self, apdu: &ApduHeader) -> bool {
        // Check if masked value is allowed at each position (CLA, INS, P1, P2).
        izip!(apdu.0, self.mask, self.allowed).all(|(apdu, mask, allow)| apdu & mask == allow)
    }
}

impl std::fmt::Debug for ApduFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ApduFilter: allowed {} mask {}",
            hex::encode(self.allowed),
            hex::encode(self.mask)
        )
    }
}

/// Defines an NFC access rule.
///
/// Corresponds to NFC-AR-DO (pg. 71).
#[derive(Clone, Copy, Debug, PartialEq)]
enum NfcAccessRule {
    Always,
    Never,
}

impl NfcAccessRule {
    /// Create [`NfcAccessRule`] from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::NfcArDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Self::from_data(data),
            _ => bail!("Invalid content {} in NfcArDo", tlv.value()),
        }
    }

    /// Create [`NfcAccessRule`] from a buffer containing the content of an NFC-AR-DO object.
    fn from_data(data: &[u8]) -> Result<Self> {
        ensure!(data.len() == 1, "Invalid data length in NfcArDo {}", hex::encode(data));
        match data[0] {
            0 => Ok(Self::Never),
            1 => Ok(Self::Always),
            _ => bail!("Invalid data in NfcArDo {}", hex::encode(data)),
        }
    }

    /// Merge the other access rule into self, taking the more restrictive.
    fn merge(&mut self, other: Self) {
        match self {
            NfcAccessRule::Always => *self = other,
            NfcAccessRule::Never => {}
        }
    }
}

/// Determine if the referenced object contains a known tag.
fn is_known_tag(tlv: &tlv::Object) -> bool {
    if cfg!(feature = "disallow_unknown_ara_tags") {
        // If we're disallowing unknown ARA tags, this function just claims all tags as known,
        // allowing the rest of the code to see the unknown tags and emit errors.
        true
    } else {
        let known = !matches!(tlv.tag(), tlv::Tag::Unknown(_));
        if !known {
            info!("Ignoring tag {:?}", tlv.tag());
        }
        known
    }
}

impl From<[u8; SHA256_LEN]> for Sha256Digest {
    fn from(value: [u8; SHA256_LEN]) -> Self {
        Sha256Digest(value)
    }
}

impl TryFrom<&[u8]> for Sha256Digest {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl AsRef<[u8]> for Sha256Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SHA-256 digest: [{}] ", hex::encode(self.0))
    }
}

impl From<[u8; SHA1_OR_UUID_LEN]> for Sha1DigestOrUuid {
    fn from(value: [u8; SHA1_OR_UUID_LEN]) -> Self {
        Sha1DigestOrUuid(value)
    }
}

impl TryFrom<&[u8]> for Sha1DigestOrUuid {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl AsRef<[u8]> for Sha1DigestOrUuid {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Sha1DigestOrUuid {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "SHA-1 digest or UUID: [{}] ", hex::encode(self.0))
    }
}
