use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    Generation, HealthPolicy, OverlayAddress, PeerId, Permission, PolicyError, VpnPeer,
    WireGuardPublicKey,
};

const SCHEMA_VERSION: u8 = 1;
const WG_USERS: &str = "wg-users";
const WG_NODES: &str = "wg-nodes";

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GatewayId(PeerId);

impl GatewayId {
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        PeerId::new(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for GatewayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl<'de> Deserialize<'de> for GatewayId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct GatewayPeer {
    peer_id: PeerId,
    public_key: WireGuardPublicKey,
    address: OverlayAddress,
    health_policy: HealthPolicy,
    permissions: Vec<Permission>,
}

impl From<VpnPeer> for GatewayPeer {
    fn from(peer: VpnPeer) -> Self {
        Self {
            peer_id: peer.peer_id().clone(),
            public_key: peer.public_key().clone(),
            address: peer.address(),
            health_policy: peer.health_policy(),
            permissions: peer.permissions(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerManifest {
    schema_version: u8,
    interface: String,
    generation: Generation,
    generated_at: String,
    peers: Vec<GatewayPeer>,
}

impl PeerManifest {
    pub fn new(
        generation: Generation,
        generated_at: impl Into<String>,
        peers: impl IntoIterator<Item = VpnPeer>,
    ) -> Result<Self, PolicyError> {
        let generated_at = generated_at.into();
        if !valid_utc_timestamp(&generated_at) {
            return Err(PolicyError::InvalidGeneratedAt);
        }

        let mut peers = peers.into_iter().map(GatewayPeer::from).collect::<Vec<_>>();
        if peers.len() > 253 {
            return Err(PolicyError::TooManyPeers);
        }
        peers.sort_by(|left, right| left.peer_id.cmp(&right.peer_id));

        let mut peer_ids = HashSet::new();
        let mut public_keys = HashSet::new();
        let mut addresses = HashSet::new();
        for peer in &peers {
            if !peer_ids.insert(peer.peer_id.clone())
                || !public_keys.insert(peer.public_key.clone())
                || !addresses.insert(peer.address)
            {
                return Err(PolicyError::DuplicatePeerIdentity);
            }
        }

        Ok(Self {
            schema_version: SCHEMA_VERSION,
            interface: WG_USERS.to_owned(),
            generation,
            generated_at,
            peers,
        })
    }

    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn digest(&self) -> Result<ManifestDigest, PolicyError> {
        let value = serde_json::to_value(self).map_err(|_| PolicyError::Serialization)?;
        let mut canonical = String::new();
        write_canonical_json(&value, &mut canonical)?;
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(ManifestDigest(format!("{digest:x}")))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ManifestDigest(String);

impl ManifestDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(PolicyError::Serialization)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ManifestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ManifestDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedInterface {
    interface: String,
    generation: Generation,
    manifest_digest: ManifestDigest,
}

impl AppliedInterface {
    #[must_use]
    pub fn wg_users(generation: Generation, manifest_digest: ManifestDigest) -> Self {
        Self {
            interface: WG_USERS.to_owned(),
            generation,
            manifest_digest,
        }
    }

    #[must_use]
    pub fn is_wg_users(&self) -> bool {
        self.interface == WG_USERS
    }

    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &ManifestDigest {
        &self.manifest_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayStateReport {
    schema_version: u8,
    gateway_id: GatewayId,
    applied: Vec<AppliedInterface>,
}

impl GatewayStateReport {
    #[must_use]
    pub fn new(gateway_id: GatewayId, applied: Vec<AppliedInterface>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            gateway_id,
            applied,
        }
    }

    #[must_use]
    pub fn gateway_id(&self) -> &GatewayId {
        &self.gateway_id
    }

    #[must_use]
    pub fn wg_users(&self) -> Option<&AppliedInterface> {
        self.applied.iter().find(|state| state.is_wg_users())
    }

    #[must_use]
    pub fn is_supported(&self) -> bool {
        let interfaces = self
            .applied
            .iter()
            .map(|state| state.interface.as_str())
            .collect::<HashSet<_>>();
        self.schema_version == SCHEMA_VERSION
            && self.applied.len() <= 2
            && interfaces.len() == self.applied.len()
            && interfaces
                .iter()
                .all(|interface| *interface == WG_USERS || *interface == WG_NODES)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDelivery {
    schema_version: u8,
    gateway_id: GatewayId,
    delivery_id: String,
    manifest_digest: ManifestDigest,
    manifest: PeerManifest,
}

impl PeerDelivery {
    pub fn new(gateway_id: GatewayId, manifest: PeerManifest) -> Result<Self, PolicyError> {
        let manifest_digest = manifest.digest()?;
        let delivery_id = format!(
            "wg-users-{}-{}",
            manifest.generation().get(),
            &manifest_digest.as_str()[..12]
        );
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            gateway_id,
            delivery_id,
            manifest_digest,
            manifest,
        })
    }

    #[must_use]
    pub fn gateway_id(&self) -> &GatewayId {
        &self.gateway_id
    }

    #[must_use]
    pub fn delivery_id(&self) -> &str {
        &self.delivery_id
    }

    #[must_use]
    pub fn manifest_digest(&self) -> &ManifestDigest {
        &self.manifest_digest
    }

    #[must_use]
    pub fn manifest(&self) -> &PeerManifest {
        &self.manifest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAcknowledgement {
    schema_version: u8,
    gateway_id: GatewayId,
    delivery_id: String,
    interface: String,
    generation: Generation,
    manifest_digest: ManifestDigest,
    outcome: String,
}

impl GatewayAcknowledgement {
    #[must_use]
    pub fn applied(delivery: &PeerDelivery) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            gateway_id: delivery.gateway_id.clone(),
            delivery_id: delivery.delivery_id.clone(),
            interface: WG_USERS.to_owned(),
            generation: delivery.manifest.generation,
            manifest_digest: delivery.manifest_digest.clone(),
            outcome: "applied".to_owned(),
        }
    }

    #[must_use]
    pub fn matches(&self, delivery: &PeerDelivery) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.gateway_id == delivery.gateway_id
            && self.delivery_id == delivery.delivery_id
            && self.interface == WG_USERS
            && self.generation == delivery.manifest.generation
            && self.manifest_digest == delivery.manifest_digest
            && self.outcome == "applied"
    }

    #[must_use]
    pub fn gateway_id(&self) -> &GatewayId {
        &self.gateway_id
    }
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 20
        && value.ends_with('Z')
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[11..13].iter().all(u8::is_ascii_digit)
        && bytes[14..16].iter().all(u8::is_ascii_digit)
        && bytes[17..19].iter().all(u8::is_ascii_digit)
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), PolicyError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(|_| PolicyError::Serialization)?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output
                    .push_str(&serde_json::to_string(key).map_err(|_| PolicyError::Serialization)?);
                output.push(':');
                write_canonical_json(&values[*key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    use super::*;
    use crate::{UserId, VpnPolicy};

    fn manifest() -> PeerManifest {
        let mut policy = VpnPolicy::default();
        policy
            .enroll(
                UserId::new("user-1").expect("valid ID"),
                PeerId::new("peer-1").expect("valid ID"),
                WireGuardPublicKey::new(STANDARD.encode([1_u8; 32])).expect("valid key"),
                false,
            )
            .expect("peer enrolls");
        policy
            .manifest("2026-08-01T20:00:00Z")
            .expect("manifest builds")
    }

    #[test]
    fn serializes_the_gateway_contract_without_user_identity() {
        let value = serde_json::to_value(manifest()).expect("manifest serializes");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["interface"], "wg-users");
        assert_eq!(value["peers"][0]["peer_id"], "peer-1");
        assert_eq!(
            value["peers"][0]["permissions"],
            serde_json::json!(["egress"])
        );
        assert!(!value.to_string().contains("user-1"));
    }

    #[test]
    fn digest_matches_python_style_sorted_compact_json() {
        let manifest = manifest();
        let value = serde_json::to_value(&manifest).expect("manifest serializes");
        let mut canonical = String::new();
        write_canonical_json(&value, &mut canonical).expect("canonicalization succeeds");

        assert!(!canonical.contains(' '));
        assert!(canonical.starts_with("{\"generated_at\":"));
        assert_eq!(
            manifest.digest().expect("digest succeeds").as_str().len(),
            64
        );
    }

    #[test]
    fn delivery_and_acknowledgement_bind_the_exact_manifest() {
        let delivery =
            PeerDelivery::new(GatewayId::new("gateway-1").expect("valid ID"), manifest())
                .expect("delivery builds");
        let acknowledgement = GatewayAcknowledgement::applied(&delivery);

        assert!(acknowledgement.matches(&delivery));
        assert!(delivery.delivery_id().starts_with("wg-users-2-"));
    }
}
