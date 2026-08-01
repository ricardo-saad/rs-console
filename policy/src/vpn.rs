use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{PeerManifest, PolicyError};

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
                let value = value.into();
                if valid_opaque_id(&value) {
                    Ok(Self(value))
                } else {
                    Err(PolicyError::InvalidIdentifier)
                }
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

opaque_id!(UserId);
opaque_id!(PeerId);

fn valid_opaque_id(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    value.len() <= 128
        && first.is_ascii_alphanumeric()
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':' | '-')
        })
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WireGuardPublicKey(String);

impl WireGuardPublicKey {
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        let decoded = STANDARD
            .decode(value.as_bytes())
            .map_err(|_| PolicyError::InvalidPublicKey)?;
        if value.len() == 44 && value.ends_with('=') && decoded.len() == 32 {
            Ok(Self(value))
        } else {
            Err(PolicyError::InvalidPublicKey)
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WireGuardPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OverlayAddress(Ipv4Addr);

impl OverlayAddress {
    pub fn new(host: u8) -> Result<Self, PolicyError> {
        if (2..=254).contains(&host) {
            Ok(Self(Ipv4Addr::new(10, 100, 0, host)))
        } else {
            Err(PolicyError::InvalidAddress)
        }
    }

    #[must_use]
    pub fn host(self) -> u8 {
        self.0.octets()[3]
    }
}

impl fmt::Display for OverlayAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/32", self.0)
    }
}

impl FromStr for OverlayAddress {
    type Err = PolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let address = value
            .strip_suffix("/32")
            .ok_or(PolicyError::InvalidAddress)?
            .parse::<Ipv4Addr>()
            .map_err(|_| PolicyError::InvalidAddress)?;
        let octets = address.octets();
        if octets[..3] == [10, 100, 0] && (2..=254).contains(&octets[3]) {
            Ok(Self(address))
        } else {
            Err(PolicyError::InvalidAddress)
        }
    }
}

impl Serialize for OverlayAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OverlayAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthPolicy {
    Required,
    OnDemand,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Egress,
    Games,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    pub fn new(value: u64) -> Result<Self, PolicyError> {
        if value == 0 {
            Err(PolicyError::InvalidGeneration)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("generation exhausted"))
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VpnPeer {
    user_id: UserId,
    peer_id: PeerId,
    public_key: WireGuardPublicKey,
    address: OverlayAddress,
    health_policy: HealthPolicy,
    games: bool,
}

impl VpnPeer {
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    #[must_use]
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    #[must_use]
    pub fn public_key(&self) -> &WireGuardPublicKey {
        &self.public_key
    }

    #[must_use]
    pub fn address(&self) -> OverlayAddress {
        self.address
    }

    #[must_use]
    pub fn health_policy(&self) -> HealthPolicy {
        self.health_policy
    }

    #[must_use]
    pub fn permissions(&self) -> Vec<Permission> {
        let mut permissions = vec![Permission::Egress];
        if self.games {
            permissions.push(Permission::Games);
        }
        permissions
    }
}

#[derive(Clone, Debug)]
pub struct VpnPolicy {
    generation: Generation,
    peers: BTreeMap<PeerId, VpnPeer>,
}

impl Default for VpnPolicy {
    fn default() -> Self {
        Self {
            generation: Generation(1),
            peers: BTreeMap::new(),
        }
    }
}

impl VpnPolicy {
    #[must_use]
    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn peers(&self) -> impl Iterator<Item = &VpnPeer> {
        self.peers.values()
    }

    pub fn enroll(
        &mut self,
        user_id: UserId,
        peer_id: PeerId,
        public_key: WireGuardPublicKey,
        games: bool,
    ) -> Result<VpnPeer, PolicyError> {
        if self.peers.contains_key(&peer_id)
            || self
                .peers
                .values()
                .any(|peer| peer.public_key == public_key)
        {
            return Err(PolicyError::PeerAlreadyExists);
        }
        let address = self.allocate_address()?;
        let peer = VpnPeer {
            user_id,
            peer_id: peer_id.clone(),
            public_key,
            address,
            health_policy: HealthPolicy::OnDemand,
            games,
        };
        self.peers.insert(peer_id, peer.clone());
        self.generation = self.generation.next();
        Ok(peer)
    }

    pub fn set_games(&mut self, peer_id: &PeerId, enabled: bool) -> Result<bool, PolicyError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PolicyError::PeerNotFound)?;
        if peer.games == enabled {
            return Ok(false);
        }
        peer.games = enabled;
        self.generation = self.generation.next();
        Ok(true)
    }

    pub fn rotate_key(
        &mut self,
        peer_id: &PeerId,
        public_key: WireGuardPublicKey,
    ) -> Result<bool, PolicyError> {
        if self
            .peers
            .iter()
            .any(|(existing_id, peer)| existing_id != peer_id && peer.public_key == public_key)
        {
            return Err(PolicyError::DuplicatePeerIdentity);
        }
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or(PolicyError::PeerNotFound)?;
        if peer.public_key == public_key {
            return Ok(false);
        }
        peer.public_key = public_key;
        self.generation = self.generation.next();
        Ok(true)
    }

    pub fn revoke(&mut self, peer_id: &PeerId) -> Result<VpnPeer, PolicyError> {
        let peer = self
            .peers
            .remove(peer_id)
            .ok_or(PolicyError::PeerNotFound)?;
        self.generation = self.generation.next();
        Ok(peer)
    }

    pub fn manifest(&self, generated_at: impl Into<String>) -> Result<PeerManifest, PolicyError> {
        PeerManifest::new(self.generation, generated_at, self.peers.values().cloned())
    }

    fn allocate_address(&self) -> Result<OverlayAddress, PolicyError> {
        let used = self
            .peers
            .values()
            .map(|peer| peer.address.host())
            .collect::<HashSet<_>>();
        (2..=254)
            .find(|host| !used.contains(host))
            .map(OverlayAddress::new)
            .transpose()?
            .ok_or(PolicyError::AddressPoolExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> WireGuardPublicKey {
        WireGuardPublicKey::new(STANDARD.encode([byte; 32])).expect("test key is valid")
    }

    #[test]
    fn allocates_stable_addresses_and_additive_permissions() {
        let mut policy = VpnPolicy::default();
        let first_id = PeerId::new("peer-a").expect("valid ID");
        let second_id = PeerId::new("peer-b").expect("valid ID");

        let first = policy
            .enroll(
                UserId::new("user-a").expect("valid ID"),
                first_id.clone(),
                key(1),
                false,
            )
            .expect("peer enrolls");
        assert_eq!(first.address().to_string(), "10.100.0.2/32");
        assert_eq!(first.permissions(), vec![Permission::Egress]);

        policy
            .enroll(
                UserId::new("user-b").expect("valid ID"),
                second_id,
                key(2),
                true,
            )
            .expect("peer enrolls");
        assert!(policy.set_games(&first_id, true).expect("peer exists"));
        assert!(!policy.set_games(&first_id, true).expect("peer exists"));
        assert_eq!(policy.generation().get(), 4);
    }

    #[test]
    fn rejects_server_or_network_addresses() {
        assert!(OverlayAddress::new(0).is_err());
        assert!(OverlayAddress::new(1).is_err());
        assert!(OverlayAddress::new(255).is_err());
        assert!("10.100.2.2/32".parse::<OverlayAddress>().is_err());
    }

    #[test]
    fn no_op_changes_do_not_advance_generation() {
        let mut policy = VpnPolicy::default();
        let peer_id = PeerId::new("peer-a").expect("valid ID");
        policy
            .enroll(
                UserId::new("user-a").expect("valid ID"),
                peer_id.clone(),
                key(1),
                false,
            )
            .expect("peer enrolls");
        let generation = policy.generation();

        assert!(!policy.set_games(&peer_id, false).expect("peer exists"));
        assert!(!policy.rotate_key(&peer_id, key(1)).expect("peer exists"));
        assert_eq!(policy.generation(), generation);
    }
}
