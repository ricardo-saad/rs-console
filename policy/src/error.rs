use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum PolicyError {
    #[error("identifier must be an opaque ASCII identifier of at most 128 characters")]
    InvalidIdentifier,
    #[error("WireGuard public key must be canonical base64 for exactly 32 bytes")]
    InvalidPublicKey,
    #[error("address must be a usable /32 inside 10.100.0.0/24")]
    InvalidAddress,
    #[error("generation must be positive")]
    InvalidGeneration,
    #[error("generated_at must be an RFC 3339 UTC timestamp ending in Z")]
    InvalidGeneratedAt,
    #[error("manifest contains more than 253 peers")]
    TooManyPeers,
    #[error("peer identity, public key, and address must each be unique")]
    DuplicatePeerIdentity,
    #[error("peer already exists")]
    PeerAlreadyExists,
    #[error("peer does not exist")]
    PeerNotFound,
    #[error("the wg-users address pool is exhausted")]
    AddressPoolExhausted,
    #[error("canonical JSON serialization failed")]
    Serialization,
}
