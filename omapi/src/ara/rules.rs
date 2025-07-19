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

use super::{tlv, xml};
use anyhow::{anyhow, bail, ensure, Context, Result};
use itertools::{izip, Itertools};
use log::{trace, warn};
use std::{
    array::TryFromSliceError,
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

#[cfg(test)]
mod test;

pub const SHA1_OR_UUID_LEN: usize = 20;
pub const SHA256_LEN: usize = 32;
pub const APDU_HEADER_LEN: usize = 4;
/// An APDU filter set consists of two byte arrays the same length as an APDU header.  One is a
/// mask that is bitwise ANDed with the header and the other is a pattern that is compared with
/// the mask result.
pub const APDU_FILTER_SET_LEN: usize = 2 * APDU_HEADER_LEN;

/// Trait for types that can be converted from a tlv::Object.
trait ConvertibleFromTlv: Sized {
    /// Convert the [`tlv::Object`] to `Self`, or return an error if the object structure is
    /// incorrect.
    fn from_tlv(tlv: tlv::Object) -> Result<Self>;
}

/// Trait for types that can be converted from a vector of tlv::Objects.  The objects in the
/// vector get mapped to fields in the resulting type.
trait ConvertibleFromTlvVec: Sized {
    /// Return the tag of the parent [`tlv::Object`] in which the vector is found.
    fn parent_tag() -> tlv::Tag;

    /// Convert the vector of [`tlv::Objects`] to field values and assemble them, or return an
    /// error if some part of the structure is incorrect.
    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self>;
}

/// All types that are convertible from a TLV vector are first converted from a single TLV object
/// that contains that vector.  We implement this step generically.
impl<T: ConvertibleFromTlvVec> ConvertibleFromTlv for T {
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == T::parent_tag());
        match tlv.get_content() {
            tlv::Value::Constructed(vec) => T::from_tlv_vec(vec),
            other => bail!("Invalid content {other} for {}", T::parent_tag()),
        }
    }
}

/// SHA-256 digest of an application certificate
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sha256Digest(pub [u8; SHA256_LEN]);

/// Either a SHA-1 digest of an application certificate or a 20-byte UUID.  These are different
/// things, but because ARA rules don't distinguish between them it's impossible to know which one
/// is meant when a 20-byte identifier is found in a rule.  So this type contains some sort of
/// 20-byte value and we match it against both SHA-1 digests and UUIDs.
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
/// enum.  The reason for the naming is that "Least" to "Highest" are the
/// priorities defined by the ARA-M specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RuleSpecificity {
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
pub struct RuleSet {
    /// ARA rules to be applied.  Will be checked in the order they're found in the vector, which
    /// means they must be ordered correctly when the [`RuleSet`] is created.
    rules: Vec<Rule>,
}

impl RuleSet {
    /// This method constructs a [`RuleSet`] from an iterator over [`Rule`]s, but it does some
    /// extra work to implement ARA-M meta-rules that would be applied at evaluation time, i.e.  when
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
    ///     [`AraMMatchCriteria::cmp`], which is defined to produce the correct order.  Sorting is
    ///     provided by the [`BTreeMap`].
    ///
    /// By applying these optimizations now, we don't have to bother with these meta-rules at
    /// evaluation time.  We can just apply the rules sequentially, taking the first match.
    ///
    /// For ARA-D rules there is no pre-processing to be done, but the ARA-D rules are higher in
    /// priority than ARA-M rules, and so must come first in the final map.
    pub fn new<I>(rules_iter: I) -> Self
    where
        I: IntoIterator<Item = Rule>,
    {
        let mut ara_m_rules: BTreeMap<AraMMatchCriteria, AraMAccessRules> = BTreeMap::new();
        let mut ara_d_rules: Vec<Rule> = Vec::new();

        for rule in rules_iter {
            match rule {
                Rule::AraM { criteria, access } => {
                    ara_m_rules
                        .entry(criteria)
                        .and_modify(|entry| {
                            entry.merge(&access);
                        })
                        .or_insert(access);
                }
                Rule::AraD { .. } => {
                    ara_d_rules.push(rule);
                }
            }
        }

        handle_aid_shadowing_rule(&mut ara_m_rules);
        handle_app_shadowing(&mut ara_m_rules);

        let mut rules = ara_d_rules;
        rules.extend(ara_m_rules.into_iter().map(Rule::from_ara_m_tuple));

        RuleSet { rules }
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
    fn get_rules(&self, app: &DeviceAppId, aid: &AppletId) -> &AraMAccessRules {
        self.rules
            .iter()
            .find_map(|rule| rule.matches(app, aid).then_some(rule.access()))
            .unwrap_or(&AraMAccessRules::NEVER)
    }
}

/// Handle AID shadowing by setting [`AccessRules::NEVER`] for any app-wildcard rule (i.e.
/// [`RuleSpecificity::High`]) with an AID that is mentioned in a fully-specified (i.e.
/// [`RuleSpecificity::Highest`] rule.
fn handle_aid_shadowing_rule(rules: &mut BTreeMap<AraMMatchCriteria, AraMAccessRules>) {
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
            *access = AraMAccessRules::NEVER;
        }
    }
}

/// Handle app shadowing by removing any fully-generic rules ([`RuleSpecificity::Least`]) if any
/// AID-wildcard ([`RuleSpecificity::Low`]) rules exist.
///
/// We search in reverse order because [`Iterator::any`] short-circuits and
/// [`RuleSpecificity::Low`] rules are towards the end of the rule set. Minor efficiency tweak.
fn handle_app_shadowing(rules: &mut BTreeMap<AraMMatchCriteria, AraMAccessRules>) {
    if rules.iter().rev().any(|(criteria, _)| criteria.specificity() == RuleSpecificity::Low) {
        rules.retain(|criteria, _| criteria.specificity() != RuleSpecificity::Least);
    };
}

/// Convert a TLV object containing ARA-M rules to a [`Vec<Rule>`], preparatory to creating a
/// [`RuleSet`] (perhaps containing rules from multiple sources).
pub fn build_rules_from_ara_m_tlv(tlv: tlv::Object) -> Result<Vec<Rule>> {
    parse_rule_set(tlv, Rule::from_ara_m_tlv).context("Parsing ARA-M rules")
}

/// Convert a TLV object containing ARA-D rules to a [`Vec<Rule>`], preparatory to creating a
/// [`RuleSet`] (perhaps containing rules from multiple sources).
pub fn build_rules_from_ara_d_tlv(tlv: tlv::Object) -> Result<Vec<Rule>> {
    parse_rule_set(tlv, Rule::from_ara_d_tlv).context("Parsing ARA-D rules")
}

/// An access rule, specifying the conditions of match and the access permissions/restrictions to
/// be applied.
///
/// Corresponds to REF-AR-DO.  See ARA-M page 68.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    AraM { criteria: AraMMatchCriteria, access: AraMAccessRules },
    AraD { criteria: AraDMatchCriteria, access: AraDAccessRules },
}

impl Rule {
    /// Create a [`Rule::AraM`] from a tuple of a [`usize`] and a [`tlv::Object`].  The [`usize`]
    /// represents the position of the object in higher-level structure and is used only for error
    /// reporting.  Returns [`Err`] if the object does not contain a valid ARA-M REF-AR-DO
    /// structure.
    pub(crate) fn from_ara_m_tlv(entry: (usize, tlv::Object)) -> Result<Self> {
        let (pos, tlv) = entry;
        Self::from_tlv(tlv, Self::from_ara_m_tuple)
            .with_context(|| format!("Parsing ARA-M RefArDo at pos {pos}"))
    }

    /// Create a [`Rule::AraD`] from a tuple of a [`usize`] and a [`tlv::Object`].  The [`usize`]
    /// represents the position of hte object in higher-level structure and is used only for error
    /// reporting.  Returns [`Err`] if the object does not contain a valid ARA-D REF-AR-DO
    /// structure.
    pub(crate) fn from_ara_d_tlv(entry: (usize, tlv::Object)) -> Result<Self> {
        let (pos, tlv) = entry;
        Self::from_tlv(tlv, Self::from_ara_d_tuple)
            .with_context(|| format!("Parsing ARA-D RefArDo at pos {pos}"))
    }

    /// Create a [`Rule`] from an [`xml::RefArDo`].  Returns [`Err`] if the object does not
    /// contain a valid ARA-M REF-AR-DO structure.
    pub fn from_xml(ref_ar_do: xml::RefArDo) -> Result<Self> {
        let criteria = AraMMatchCriteria::from_xml(ref_ar_do.get_match_criteria())?;
        let access = AraMAccessRules::from_xml(ref_ar_do.get_apdu_access())?;
        Ok(Rule::AraM { criteria, access })
    }

    /// Returns true iff this rule matches the given app and applet.
    pub fn matches(&self, app: &DeviceAppId, aid: &AppletId) -> bool {
        match self {
            Rule::AraM { criteria, .. } => criteria.matches(app, aid),
            Rule::AraD { criteria, .. } => criteria.matches(app),
        }
    }

    /// Returns a reference to the access rules for this rule.
    ///
    /// It's a little odd that we return ARA-M access specification for both ARA-M and ARA-D
    /// rules, but the ARA-D specification doesn't detail what "device access" is intented to
    /// mean, and Android interprets it as "all access", so we treat ARA-D device access
    /// permission as the same as a maximally-permissive ARA-M rule.
    pub fn access(&self) -> &AraMAccessRules {
        match self {
            Rule::AraM { access, .. } => access,
            Rule::AraD { access, .. } => access.to_ara_m_access(),
        }
    }

    /// Create a [`Rule`] from a [`tlv::Object`] containing an ARA rule structure.  The type of
    /// ARA rule is specified by the generic arguments (which are inferred from the
    /// `from_tuple_fn` type).
    fn from_tlv<MatchCriteria: ConvertibleFromTlv, AccessRules: ConvertibleFromTlv>(
        tlv: tlv::Object,
        from_tuple_fn: impl FnOnce((MatchCriteria, AccessRules)) -> Self,
    ) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::RefArDo);
        let value = tlv.get_content();
        let tlv::Value::Constructed(vec) = value else {
            bail!("Invalid RefArDo content {}", value);
        };

        let mut iter = vec.into_iter().enumerate().filter(should_handle);

        let criteria = {
            let (pos, entry) = iter.next().ok_or_else(|| anyhow!("Missing RefDo"))?;
            ensure!(
                *entry.tag() == tlv::Tag::RefDo,
                "Expected RefDo, found {} at pos {pos}",
                entry.tag()
            );
            MatchCriteria::from_tlv(entry).with_context(|| format!("Parsing RefDo at pos {pos}"))?
        };

        let access = {
            let (pos, entry) = iter.next().ok_or_else(|| anyhow!("Missing ArDo"))?;
            ensure!(
                *entry.tag() == tlv::Tag::ArDo,
                "Expected ArDo, found {} at pos {pos}",
                entry.tag()
            );
            AccessRules::from_tlv(entry).with_context(|| format!("Parsing ArDo at pos {pos}"))?
        };

        if let Some((pos, entry)) = iter.next() {
            bail!("Extra entry {} at pos {pos}", entry.tag());
        }

        Ok(from_tuple_fn((criteria, access)))
    }

    /// Construct a [`Rule::AraM`] from a tuple of components.
    fn from_ara_m_tuple(tuple: (AraMMatchCriteria, AraMAccessRules)) -> Self {
        let (criteria, access) = tuple;
        Self::AraM { criteria, access }
    }

    /// Construct a [`Rule::AraD`] from a tuple of components.
    fn from_ara_d_tuple(tuple: (AraDMatchCriteria, AraDAccessRules)) -> Self {
        let (criteria, access) = tuple;
        Self::AraD { criteria, access }
    }
}

/// Defines the ARA-M rule matching conditions
///
/// The order in which rules are applied depends on their match criteria.  This type implements
/// [`Ord`] so sorted rules are in the order the specification requires them to be evaluated.
///
/// Corresponds to REF-DO.  See ARA-M page 68.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AraMMatchCriteria {
    aid_ref: AppletRef,
    hash_ref: DeviceAppIdRef,
}

impl AraMMatchCriteria {
    /// Create [`MatchCriteria`] from [`xml::RefDo`].
    fn from_xml(ref_do: &xml::RefDo) -> Result<AraMMatchCriteria> {
        Ok(AraMMatchCriteria {
            aid_ref: AppletRef::from_xml(ref_do.get_aid_ref())?,
            hash_ref: DeviceAppIdRef::from_xml(ref_do.get_app_id())?,
        })
    }

    /// Returns true iff these MatchCriteria match the supplied app ID and applet ID.
    fn matches(&self, app_id: &DeviceAppId, aid: &AppletId) -> bool {
        self.aid_ref.matches(aid) && self.hash_ref.matches(app_id)
    }

    /// Calculate the specificity-derived priority of a rule from the booleans indicating whether
    /// the rule specifies a specific AID and/or [`super::DeviceAppId`].  See the priority table
    /// on ARA-M page 27.
    fn specificity(&self) -> RuleSpecificity {
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

impl ConvertibleFromTlvVec for AraMMatchCriteria {
    fn parent_tag() -> tlv::Tag {
        tlv::Tag::RefDo
    }

    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self> {
        ensure!(!vec.is_empty(), "Found empty ARA-M RefDo");

        let mut iter = vec.into_iter().enumerate().filter(should_handle);

        let aid_ref = match iter.next() {
            Some((pos, entry))
                if *entry.tag() == tlv::Tag::AidRefDoSpecificApplet
                    || *entry.tag() == tlv::Tag::AidRefDoImplicit =>
            {
                AppletRef::from_tlv(entry)
                    .with_context(|| format!("Parsing RefDo at pos {}", pos))?
            }
            Some((pos, entry)) => {
                bail!("Invalid tag {} in REF-DO, expected AID-REF-DO at pos {pos}", entry.tag())
            }
            None => bail!("Missing AID-REF-DO"),
        };

        let hash_ref = match iter.next() {
            Some((pos, entry)) if *entry.tag() == tlv::Tag::DeviceAppIdRefDo => {
                DeviceAppIdRef::from_tlv(entry)
                    .with_context(|| format!("Parsing RefDo at pos {}", pos))?
            }
            Some((pos, entry)) => {
                bail!(
                    "Invalid tag {} in REF-DO, expected DeviceAppID-REF-DO at pos {pos}",
                    entry.tag()
                )
            }
            None => bail!("Missing DeviceAppId-REF-DO"),
        };

        if let Some((pos, entry)) = iter.next() {
            bail!("Found unexpected {} in REF-DO at pos {pos}", entry.tag());
        }

        Ok(Self { aid_ref, hash_ref })
    }
}

impl PartialOrd for AraMMatchCriteria {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AraMMatchCriteria {
    fn cmp(&self, other: &Self) -> Ordering {
        self.specificity()
            .cmp(&other.specificity())
            .then(self.hash_ref.cmp(&other.hash_ref))
            .then(self.aid_ref.cmp(&other.aid_ref))
    }
}

/// Defines the ARA-D rule conditions for access.
///
/// Corresponds to REF-DO.  See ARA-D page 41.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AraDMatchCriteria {
    hash_ref: DeviceAppIdRef,
    pkg_ref: Option<DeviceAppPkgRef>,
}

impl AraDMatchCriteria {
    /// Returns true iff these MatchCriteria match the supplied app ID.
    fn matches(&self, app_id: &DeviceAppId) -> bool {
        self.hash_ref.matches(app_id) && self.pkg_ref.as_ref().is_none_or(|p| p.matches(app_id))
    }
}

impl ConvertibleFromTlvVec for AraDMatchCriteria {
    fn parent_tag() -> tlv::Tag {
        tlv::Tag::RefDo
    }

    /// Create [`MatchCriteria`] from a vector containing a DeviceAppId-REF-DO and an optional
    /// PKG-REF-DO.
    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self> {
        ensure!(!vec.is_empty(), "Found empty ARA-D RefDo");

        let mut iter = vec.into_iter().enumerate().filter(should_handle);
        let hash_ref = match iter.next() {
            Some((pos, entry)) if *entry.tag() == tlv::Tag::DeviceAppIdRefDo => {
                DeviceAppIdRef::from_tlv(entry)
                    .with_context(|| format!("Parsing RefDo at pos {pos}"))?
            }
            Some((pos, entry)) => {
                bail!(
                    "Invalid tag {} in REF-DO, expected DeviceAppID-REF-DO at pos {pos}",
                    entry.tag()
                )
            }
            None => bail!("Missing DeviceAppID-REF-DO"),
        };

        let pkg_ref = match iter.next() {
            Some((pos, entry)) if *entry.tag() == tlv::Tag::PkgRefDo => Some(
                DeviceAppPkgRef::from_tlv(entry)
                    .with_context(|| format!("Parsing RefDo at pos {pos}"))?,
            ),
            Some((pos, entry)) => {
                bail!("Invalid tag {} in REF-DO, expected PKG-REF-DO at pos {pos}", entry.tag())
            }
            None => None,
        };

        if let Some((pos, entry)) = iter.next() {
            bail!("Found unexpected {} in REF-DO at pos {pos}", entry.tag());
        }

        Ok(Self { hash_ref, pkg_ref })
    }
}

/// Defines the AID matching condition for a [`Rule`].
///
/// Corresponds to AID-REF-DO.  See ARA-M page 66.
#[derive(PartialEq, Clone, Eq, PartialOrd, Ord)]
enum AppletRef {
    AllApplets,
    DefaultApplet,
    SpecificApplet(Vec<u8>),
}

impl AppletRef {
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
            AppletRef::AllApplets => true,
            AppletRef::DefaultApplet => *applet_id == AppletId::DefaultApplet,
            AppletRef::SpecificApplet(aid) => *applet_id == AppletId::Aid(aid),
        }
    }
}

impl ConvertibleFromTlv for AppletRef {
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
}

impl std::fmt::Debug for AppletRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

impl ConvertibleFromTlv for DeviceAppIdRef {
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
}

/// Defines an app ID matching condition based on package name.
///
/// This is an ARA-D feature, not an ARA-M feature. See ARA-D page 41.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceAppPkgRef(String);

impl DeviceAppPkgRef {
    fn matches(&self, app_id: &DeviceAppId) -> bool {
        match app_id {
            DeviceAppId::Apk { sha1s: _, sha256s: _, package_names } => {
                package_names.contains(&self.0)
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

impl ConvertibleFromTlv for DeviceAppPkgRef {
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::PkgRefDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Ok(DeviceAppPkgRef(ascii_bytes_to_string(data)?)),
            value => bail!("Invalid content {} found in PkgRefDo", value),
        }
    }
}

/// Defines the conditions for access.
///
/// Corresponds to AR-DO, see ARA-M page 69.
#[derive(Debug, Clone, PartialEq)]
pub struct AraMAccessRules {
    apdu: ApduAccessRule,
    nfc: NfcAccessRule,
}

impl AraMAccessRules {
    // It's convenient to have static [`NEVER`] and `[`ALWAYS`] rules, so we can return references to them.
    const NEVER: AraMAccessRules =
        AraMAccessRules { apdu: ApduAccessRule::Never, nfc: NfcAccessRule::Never };
    const ALWAYS: AraMAccessRules =
        AraMAccessRules { apdu: ApduAccessRule::Always, nfc: NfcAccessRule::Always };

    fn from_xml(ar_do: &xml::ArDo) -> Result<Self> {
        let apdu = ApduAccessRule::from_data(ar_do.get_apdu_access())?;
        let (apdu, nfc) = handle_partial_ardo(Some(apdu), None)?;
        Ok(AraMAccessRules { apdu, nfc })
    }

    fn merge(&mut self, other: &Self) {
        self.apdu.merge(&other.apdu);
        self.nfc.merge(&other.nfc);
    }
}

impl ConvertibleFromTlvVec for AraMAccessRules {
    fn parent_tag() -> tlv::Tag {
        tlv::Tag::ArDo
    }

    /// Create [`AccessRules`] from a vector of APDU-AR-DO and NFC-AR-DO objects.
    fn from_tlv_vec(obj_vec: Vec<tlv::Object<'_>>) -> Result<Self> {
        let mut apdu = None;
        let mut nfc = None;

        for (pos, object) in obj_vec.into_iter().enumerate().filter(should_handle) {
            match object.tag() {
                tlv::Tag::ApduArDo => {
                    ensure!(
                        apdu.is_none(),
                        "Found multiple ApduArDo instances in ArDo at pos {pos}"
                    );
                    ensure!(nfc.is_none(), "Found ApduArDo instance after NfcArDo at pos {pos}");
                    apdu = Some(
                        ApduAccessRule::from_tlv(object)
                            .with_context(|| format!("Invalid ApduArDo in ArDo at pos {pos}"))?,
                    )
                }
                tlv::Tag::NfcArDo => {
                    ensure!(nfc.is_none(), "Found multiple NfcArDo instances in ArDo at pos {pos}");
                    nfc = Some(
                        NfcAccessRule::from_tlv(object)
                            .with_context(|| format!("Invalid NfcArDo in ArDo at pos {pos}"))?,
                    )
                }
                _ => bail!("Invalid tag {} in ArDo content at pos {pos}", object.tag()),
            }
        }

        let (apdu, nfc) = handle_partial_ardo(apdu, nfc)?;
        Ok(AraMAccessRules { apdu, nfc })
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

/// Defines the conditions for access.
///
/// Corresponds to AR-DO, see ARA-D page 43.
#[derive(Debug, Clone, PartialEq)]
pub struct AraDAccessRules {
    permission_rule: PermissionRule,
}

impl AraDAccessRules {
    /// Determine if APDU access is allowed.
    ///
    /// It's a little odd that we return ARA-M access specification for an ARA-D rules, but the
    /// ARA-D specification doesn't detail what "device access" is intented to mean, and Android
    /// interprets it as "all access", so we treat ARA-D device access permission as the same as a
    /// maximally-permissive ARA-M rule.
    fn to_ara_m_access(&self) -> &AraMAccessRules {
        if self.permission_rule.has_permission() {
            &AraMAccessRules::ALWAYS
        } else {
            &AraMAccessRules::NEVER
        }
    }
}

impl ConvertibleFromTlvVec for AraDAccessRules {
    fn parent_tag() -> tlv::Tag {
        tlv::Tag::ArDo
    }

    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self> {
        let mut iter = vec.into_iter().enumerate().filter(should_handle);

        let Some((pos, entry)) = iter.next() else { bail!("Missing PermArDo") };
        ensure!(*entry.tag() == tlv::Tag::PermArDo);
        let permission_rule = PermissionRule::from_tlv(entry)
            .with_context(|| format!("Parsing PermArDo at pos {pos}"))?;

        if let Some((pos, entry)) = iter.next() {
            bail!("Found unexpected {} in ArDo at pos {pos}", entry.tag());
        }

        Ok(Self { permission_rule })
    }
}

/// Defines which entities have device permissions.
///
/// This ARA-D structure is mostly undefined.  It's an eight-byte value with all but three bits
/// reserved for future use.  The defined bits are:
///
/// -  The low-order bit of the fourth byte.  If set, MNO/OEM shared permission is granted.
/// -  The low-order bit of the sixth byte.  If set, only OEM permission is granted.
/// -  The low-order bit of the seventh byte.  If set, only MNO permission is granted.
///
/// Note that the [`crate::access_enforcer::AccessEnforcer`] does not currently make any
/// distinction between OEM (device manufacturer) and MNO (mobile service provider) permissions.
/// If any permission bit is set, a matching app gets APDU access to all apps.
///
/// Corresponds to PERM-AR-DO, see ARA-D page 43.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionRule {
    mno_and_oem: bool,
    oem_only: bool,
    mno_only: bool,
}

impl PermissionRule {
    fn has_permission(&self) -> bool {
        self.mno_and_oem || self.oem_only || self.mno_only
    }
}

impl ConvertibleFromTlv for PermissionRule {
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        const MNO_OEM_BYTE: usize = 3;
        const OEM_ONLY_BYTE: usize = 5;
        const MNO_ONLY_BYTE: usize = 7;

        ensure!(*tlv.tag() == tlv::Tag::PermArDo);
        if let tlv::Value::Primitive(data) = tlv.value() {
            let data: &[u8; 8] = (*data).try_into()?;
            Ok(Self {
                mno_and_oem: data[MNO_OEM_BYTE] & 0x01 == 1,

                oem_only: data[OEM_ONLY_BYTE] & 0x01 == 1,
                mno_only: data[MNO_ONLY_BYTE] & 0x01 == 1,
            })
        } else {
            bail!("Invalid content {} in PermArDo", tlv.value());
        }
    }
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
    fn merge(&mut self, other: &Self) {
        // Take ownership of the contents of `self`.
        let mut this = ApduAccessRule::Always;
        std::mem::swap(self, &mut this);

        *self = match this {
            ApduAccessRule::Never => ApduAccessRule::Never,
            ApduAccessRule::Always => other.clone(),
            ApduAccessRule::PartialAllow(mut this_set) => match other {
                ApduAccessRule::Never => ApduAccessRule::Never,
                ApduAccessRule::Always => ApduAccessRule::PartialAllow(this_set),
                ApduAccessRule::PartialAllow(other_set) => {
                    this_set.0.extend_from_slice(other_set.0.as_slice());
                    this_set.0.sort_unstable();
                    this_set.0.dedup();
                    ApduAccessRule::PartialAllow(this_set)
                }
            },
        };
    }
}

impl ConvertibleFromTlv for ApduAccessRule {
    /// Create a new instance from a [`tlv::Object`].
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::ApduArDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Self::from_data(data),
            _ => bail!("Invalid content {} in ApduArDo", tlv.value()),
        }
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
    fn merge(&mut self, other: &Self) {
        match self {
            NfcAccessRule::Always => *self = *other,
            NfcAccessRule::Never => {}
        }
    }
}

impl ConvertibleFromTlv for NfcAccessRule {
    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
        ensure!(*tlv.tag() == tlv::Tag::NfcArDo);
        match tlv.value() {
            tlv::Value::Primitive(data) => Self::from_data(data),
            _ => bail!("Invalid content {} in NfcArDo", tlv.value()),
        }
    }
}

/// Determine if the referenced object contains a tag that should be handled.
///
/// This facilitates allowing unknown tags by (almost) silently ignoring them.  If we're allowing
/// unknown tags (the default), this function will return false to let the caller know that this
/// tag should be skipped.  It will logs a warning so the presence of unhandled tags will be noted
/// in the system log.
///
/// If we're not allowing unknown tags, this function returns true for all tags.  Because the
/// parsing code enforces strict expectations about the tags it should receive this will cause
/// unknown tags to trigger errors.
fn should_handle(entry: &(usize, tlv::Object)) -> bool {
    let (pos, tlv) = entry;
    match tlv.tag() {
        tlv::Tag::Unknown(_) if !cfg!(feature = "disallow_unknown_ara_tags") => {
            warn!("Ignoring tag {:?} at pos {pos}", tlv.tag());
            false
        }
        _ => true,
    }
}

fn parse_rule_set<T>(
    tlv: tlv::Object<'_>,
    parse_fn: fn((usize, tlv::Object<'_>)) -> Result<T>,
) -> Result<Vec<T>> {
    ensure!(*tlv.tag() == tlv::Tag::ResponseAllRefArDo);
    let value = tlv.get_content();
    match value {
        tlv::Value::Empty => Ok(Vec::new()),
        tlv::Value::Constructed(vec) => vec
            .into_iter()
            .enumerate()
            .filter(should_handle)
            .map(parse_fn)
            .collect::<Result<Vec<_>>>()
            .context("Parsing ResponseAllRefArDo"),
        tlv::Value::Primitive(_) => {
            bail!("Invalid content {} for ResponseAllRefArDo", value)
        }
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
