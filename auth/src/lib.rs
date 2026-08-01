#![forbid(unsafe_code)]

use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rs_console_policy::UserId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

pub const TOKEN_BYTES: usize = 32;

#[derive(Clone)]
pub struct SecretToken([u8; TOKEN_BYTES]);

impl SecretToken {
    #[must_use]
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn parse(value: &str) -> Result<Self, AuthError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| AuthError::InvalidToken)?;
        let bytes = decoded.try_into().map_err(|_| AuthError::InvalidToken)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    #[must_use]
    pub fn hash(&self) -> SecretHash {
        SecretHash(Sha256::digest(self.0).into())
    }
}

#[derive(Clone, Copy, Eq)]
pub struct SecretHash([u8; 32]);

impl SecretHash {
    pub fn from_slice(value: &[u8]) -> Result<Self, AuthError> {
        let bytes = value.try_into().map_err(|_| AuthError::Store)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for SecretHash {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl std::hash::Hash for SecretHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.0, state);
    }
}

impl std::fmt::Debug for SecretHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretHash([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    User,
    Operator,
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: UserId,
    pub webauthn_handle: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: Role,
    pub enabled: bool,
    pub auth_epoch: i64,
}

#[derive(Clone, Debug)]
pub struct StoredCredential {
    pub id: Uuid,
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
    pub public_data: Value,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct VerifiedCredential {
    pub credential_id: Vec<u8>,
    pub public_data: Value,
}

#[derive(Clone, Debug)]
pub struct AuthenticationVerification {
    pub credential_id: Vec<u8>,
    pub updated_public_data: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyKind {
    Registration,
    Authentication,
    OperatorBootstrap,
    OperatorRecovery,
}

#[derive(Clone, Debug)]
pub struct Ceremony {
    pub id: Uuid,
    pub kind: CeremonyKind,
    pub user_id: Option<UserId>,
    pub capability_hash: Option<SecretHash>,
    pub state: Value,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityPurpose {
    Setup,
    RecoverySetup,
    OperatorRecovery,
}

#[derive(Clone, Debug)]
pub struct Capability {
    pub id: Uuid,
    pub user_id: UserId,
    pub purpose: CapabilityPurpose,
    pub token_hash: SecretHash,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: UserId,
    pub token_hash: SecretHash,
    pub csrf_hash: SecretHash,
    pub auth_epoch: i64,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SessionGrant {
    pub token: SecretToken,
    pub csrf: SecretToken,
    pub record: SessionRecord,
}

#[derive(Clone, Debug)]
pub struct SessionPrincipal {
    pub session_id: Uuid,
    pub user: User,
    pub csrf_hash: SecretHash,
    pub absolute_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecoveryRequest {
    pub id: Uuid,
    pub user_id: UserId,
    pub requested_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditEvent {
    pub event_type: String,
    pub actor_user_id: Option<UserId>,
    pub subject_user_id: Option<UserId>,
    pub data: Value,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authentication input is invalid")]
    InvalidInput,
    #[error("token is invalid")]
    InvalidToken,
    #[error("authentication state is absent, expired, or already used")]
    InvalidState,
    #[error("request is not authenticated")]
    Unauthenticated,
    #[error("request is not authorized")]
    Forbidden,
    #[error("credential verification failed")]
    Verification,
    #[error("authentication store failed")]
    Store,
    #[error("operation conflicts with current state")]
    Conflict,
}

pub trait CeremonyEngine: Send + Sync {
    fn start_registration(
        &self,
        user: &User,
        credentials: &[StoredCredential],
    ) -> Result<(Value, Value), AuthError>;

    fn finish_registration(
        &self,
        response: &Value,
        state: &Value,
    ) -> Result<VerifiedCredential, AuthError>;

    fn start_authentication(&self) -> Result<(Value, Value), AuthError>;

    fn authentication_user_handle(&self, response: &Value) -> Result<Uuid, AuthError>;

    fn finish_authentication(
        &self,
        response: &Value,
        state: &Value,
        credentials: &[StoredCredential],
    ) -> Result<AuthenticationVerification, AuthError>;
}

#[async_trait]
pub trait AuthStore: Send + Sync {
    async fn user_by_id(&self, id: &UserId) -> Result<Option<User>, AuthError>;
    async fn user_by_handle(&self, handle: Uuid) -> Result<Option<User>, AuthError>;
    async fn credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<StoredCredential>, AuthError>;
    async fn operator_without_credential(&self) -> Result<Option<User>, AuthError>;
    async fn operator_exists(&self) -> Result<bool, AuthError>;
    async fn operator_recovery_window(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<(User, SecretHash)>, AuthError>;
    async fn capability(
        &self,
        hash: SecretHash,
        purpose: CapabilityPurpose,
        now: DateTime<Utc>,
    ) -> Result<Option<Capability>, AuthError>;
    async fn insert_capability(&self, capability: Capability) -> Result<(), AuthError>;
    async fn insert_user(
        &self,
        user: User,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError>;
    async fn approve_user_with_setup(
        &self,
        user: User,
        capability: Capability,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn rotate_all_auth_epochs(
        &self,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<u64, AuthError>;
    async fn insert_ceremony(&self, ceremony: Ceremony) -> Result<(), AuthError>;
    async fn ceremony(
        &self,
        id: Uuid,
        kind: CeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<Option<Ceremony>, AuthError>;
    async fn complete_registration(
        &self,
        ceremony_id: Uuid,
        capability_hash: Option<SecretHash>,
        credential: VerifiedCredential,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError>;
    async fn complete_authentication(
        &self,
        ceremony_id: Uuid,
        verification: AuthenticationVerification,
        session: SessionRecord,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError>;
    async fn session(
        &self,
        token_hash: SecretHash,
        now: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<Option<SessionPrincipal>, AuthError>;
    async fn rotate_session_csrf(
        &self,
        token_hash: SecretHash,
        csrf_hash: SecretHash,
        now: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<Option<SessionPrincipal>, AuthError>;
    async fn delete_session(&self, token_hash: SecretHash) -> Result<(), AuthError>;
    async fn create_recovery(
        &self,
        user_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<RecoveryRequest, AuthError>;
    async fn pending_recoveries(&self) -> Result<Vec<RecoveryRequest>, AuthError>;
    async fn approve_recovery(
        &self,
        recovery_id: Uuid,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn issue_recovery_setup(
        &self,
        recovery_id: Uuid,
        capability: Capability,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError>;
    async fn break_glass(
        &self,
        credential_id: Uuid,
        capability: Capability,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<(), AuthError>;
}

#[derive(Clone, Copy, Debug)]
pub struct AuthConfig {
    pub ceremony_ttl: Duration,
    pub capability_ttl: Duration,
    pub session_idle_ttl: Duration,
    pub session_absolute_ttl: Duration,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            ceremony_ttl: Duration::minutes(5),
            capability_ttl: Duration::minutes(15),
            session_idle_ttl: Duration::minutes(30),
            session_absolute_ttl: Duration::hours(12),
        }
    }
}

pub struct AuthService<S, E> {
    store: Arc<S>,
    engine: Arc<E>,
    config: AuthConfig,
}

impl<S, E> Clone for AuthService<S, E> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            engine: Arc::clone(&self.engine),
            config: self.config,
        }
    }
}

impl<S, E> AuthService<S, E>
where
    S: AuthStore,
    E: CeremonyEngine,
{
    #[must_use]
    pub fn new(store: Arc<S>, engine: Arc<E>, config: AuthConfig) -> Self {
        Self {
            store,
            engine,
            config,
        }
    }

    pub async fn start_setup_registration(
        &self,
        token: &SecretToken,
        purpose: CapabilityPurpose,
        now: DateTime<Utc>,
    ) -> Result<(Uuid, Value), AuthError> {
        let capability = self
            .store
            .capability(token.hash(), purpose, now)
            .await?
            .ok_or(AuthError::InvalidToken)?;
        let user = self
            .store
            .user_by_id(&capability.user_id)
            .await?
            .filter(|user| user.enabled)
            .ok_or(AuthError::InvalidToken)?;
        let credentials = self.store.credentials_for_user(&user.id).await?;
        let (challenge, state) = self.engine.start_registration(&user, &credentials)?;
        let id = Uuid::new_v4();
        self.store
            .insert_ceremony(Ceremony {
                id,
                kind: CeremonyKind::Registration,
                user_id: Some(user.id),
                capability_hash: Some(capability.token_hash),
                state,
                expires_at: now + self.config.ceremony_ttl,
            })
            .await?;
        Ok((id, challenge))
    }

    pub async fn start_operator_bootstrap(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(Uuid, Value, CeremonyKind), AuthError> {
        let (user, capability_hash, kind) =
            if let Some((user, hash)) = self.store.operator_recovery_window(now).await? {
                (user, Some(hash), CeremonyKind::OperatorRecovery)
            } else {
                (
                    self.store
                        .operator_without_credential()
                        .await?
                        .ok_or(AuthError::Conflict)?,
                    None,
                    CeremonyKind::OperatorBootstrap,
                )
            };
        let (challenge, state) = self.engine.start_registration(&user, &[])?;
        let id = Uuid::new_v4();
        self.store
            .insert_ceremony(Ceremony {
                id,
                kind,
                user_id: Some(user.id),
                capability_hash,
                state,
                expires_at: now + self.config.ceremony_ttl,
            })
            .await?;
        Ok((id, challenge, kind))
    }

    pub async fn finish_registration(
        &self,
        ceremony_id: Uuid,
        kind: CeremonyKind,
        response: &Value,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let ceremony = self
            .store
            .ceremony(ceremony_id, kind, now)
            .await?
            .ok_or(AuthError::InvalidState)?;
        let credential = self.engine.finish_registration(response, &ceremony.state)?;
        let user_id = ceremony.user_id.clone().ok_or(AuthError::InvalidState)?;
        self.store
            .complete_registration(
                ceremony.id,
                ceremony.capability_hash,
                credential,
                now,
                AuditEvent {
                    event_type: "passkey.registered".to_owned(),
                    actor_user_id: Some(user_id.clone()),
                    subject_user_id: Some(user_id),
                    data: serde_json::json!({"ceremony_kind": kind}),
                },
            )
            .await
    }

    pub async fn start_authentication(
        &self,
        now: DateTime<Utc>,
    ) -> Result<(Uuid, Value), AuthError> {
        let (challenge, state) = self.engine.start_authentication()?;
        let id = Uuid::new_v4();
        self.store
            .insert_ceremony(Ceremony {
                id,
                kind: CeremonyKind::Authentication,
                user_id: None,
                capability_hash: None,
                state,
                expires_at: now + self.config.ceremony_ttl,
            })
            .await?;
        Ok((id, challenge))
    }

    pub async fn finish_authentication(
        &self,
        ceremony_id: Uuid,
        response: &Value,
        now: DateTime<Utc>,
    ) -> Result<(SessionGrant, User), AuthError> {
        let ceremony = self
            .store
            .ceremony(ceremony_id, CeremonyKind::Authentication, now)
            .await?
            .ok_or(AuthError::InvalidState)?;
        let handle = self.engine.authentication_user_handle(response)?;
        let user = self
            .store
            .user_by_handle(handle)
            .await?
            .filter(|user| user.enabled)
            .ok_or(AuthError::Unauthenticated)?;
        let credentials = self.store.credentials_for_user(&user.id).await?;
        let verification =
            self.engine
                .finish_authentication(response, &ceremony.state, &credentials)?;
        let token = SecretToken::generate();
        let csrf = SecretToken::generate();
        let record = SessionRecord {
            id: Uuid::new_v4(),
            user_id: user.id.clone(),
            token_hash: token.hash(),
            csrf_hash: csrf.hash(),
            auth_epoch: user.auth_epoch,
            idle_expires_at: now + self.config.session_idle_ttl,
            absolute_expires_at: now + self.config.session_absolute_ttl,
        };
        self.store
            .complete_authentication(
                ceremony_id,
                verification,
                record.clone(),
                now,
                AuditEvent {
                    event_type: "session.created".to_owned(),
                    actor_user_id: Some(user.id.clone()),
                    subject_user_id: Some(user.id.clone()),
                    data: Value::Object(serde_json::Map::new()),
                },
            )
            .await?;
        Ok((
            SessionGrant {
                token,
                csrf,
                record,
            },
            user,
        ))
    }

    pub async fn authenticate_session(
        &self,
        token: &SecretToken,
        csrf: Option<&SecretToken>,
        now: DateTime<Utc>,
    ) -> Result<SessionPrincipal, AuthError> {
        let principal = self
            .store
            .session(token.hash(), now, now + self.config.session_idle_ttl)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        if let Some(csrf) = csrf {
            if csrf.hash() != principal.csrf_hash {
                return Err(AuthError::Forbidden);
            }
        }
        Ok(principal)
    }

    pub async fn issue_session_csrf(
        &self,
        token: &SecretToken,
        now: DateTime<Utc>,
    ) -> Result<(SessionPrincipal, SecretToken), AuthError> {
        let csrf = SecretToken::generate();
        let principal = self
            .store
            .rotate_session_csrf(
                token.hash(),
                csrf.hash(),
                now,
                now + self.config.session_idle_ttl,
            )
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        Ok((principal, csrf))
    }

    pub async fn logout(&self, token: &SecretToken) -> Result<(), AuthError> {
        self.store.delete_session(token.hash()).await
    }

    pub async fn request_recovery(
        &self,
        user_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<RecoveryRequest, AuthError> {
        self.store.create_recovery(user_id, now).await
    }

    pub async fn pending_recoveries(&self) -> Result<Vec<RecoveryRequest>, AuthError> {
        self.store.pending_recoveries().await
    }

    pub async fn approve_recovery(
        &self,
        recovery_id: Uuid,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        self.store
            .approve_recovery(recovery_id, operator_id, now)
            .await
    }

    pub async fn issue_recovery_setup(
        &self,
        recovery_id: Uuid,
        operator_id: &UserId,
        user_id: UserId,
        now: DateTime<Utc>,
    ) -> Result<SecretToken, AuthError> {
        let token = SecretToken::generate();
        self.store
            .issue_recovery_setup(
                recovery_id,
                Capability {
                    id: Uuid::new_v4(),
                    user_id,
                    purpose: CapabilityPurpose::RecoverySetup,
                    token_hash: token.hash(),
                    expires_at: now + self.config.capability_ttl,
                },
                operator_id,
                now,
            )
            .await?;
        Ok(token)
    }

    pub async fn approve_user_and_issue_setup(
        &self,
        operator_id: &UserId,
        user_id: UserId,
        email: String,
        display_name: String,
        now: DateTime<Utc>,
    ) -> Result<SecretToken, AuthError> {
        let email = email.trim().to_owned();
        let display_name = display_name.trim().to_owned();
        if email.is_empty() || !email.contains('@') || display_name.is_empty() {
            return Err(AuthError::InvalidInput);
        }
        if self.store.user_by_id(&user_id).await?.is_some() {
            return Err(AuthError::Conflict);
        }
        let token = SecretToken::generate();
        let user = User {
            id: user_id.clone(),
            webauthn_handle: Uuid::new_v4(),
            email,
            display_name,
            role: Role::User,
            enabled: true,
            auth_epoch: 1,
        };
        self.store
            .approve_user_with_setup(
                user,
                Capability {
                    id: Uuid::new_v4(),
                    user_id,
                    purpose: CapabilityPurpose::Setup,
                    token_hash: token.hash(),
                    expires_at: now + self.config.capability_ttl,
                },
                operator_id,
                now,
            )
            .await?;
        Ok(token)
    }

    pub async fn seed_operator(
        &self,
        user_id: UserId,
        email: String,
        display_name: String,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let email = email.trim().to_owned();
        let display_name = display_name.trim().to_owned();
        if email.is_empty() || !email.contains('@') || display_name.is_empty() {
            return Err(AuthError::InvalidInput);
        }
        if self.store.user_by_id(&user_id).await?.is_some() {
            return Err(AuthError::Conflict);
        }
        if self.store.operator_exists().await? {
            return Err(AuthError::Conflict);
        }
        self.store
            .insert_user(
                User {
                    id: user_id.clone(),
                    webauthn_handle: Uuid::new_v4(),
                    email,
                    display_name,
                    role: Role::Operator,
                    enabled: true,
                    auth_epoch: 1,
                },
                now,
                AuditEvent {
                    event_type: "operator.seeded".to_owned(),
                    actor_user_id: None,
                    subject_user_id: Some(user_id),
                    data: Value::Object(serde_json::Map::new()),
                },
            )
            .await
    }

    pub async fn rotate_all_auth_epochs(
        &self,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<u64, AuthError> {
        if reason.trim().len() < 12 {
            return Err(AuthError::InvalidInput);
        }
        self.store.rotate_all_auth_epochs(now, reason.trim()).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeEngine;

    impl CeremonyEngine for FakeEngine {
        fn start_registration(
            &self,
            _user: &User,
            _credentials: &[StoredCredential],
        ) -> Result<(Value, Value), AuthError> {
            Ok((serde_json::json!({"challenge": "register"}), json_state()))
        }

        fn finish_registration(
            &self,
            _response: &Value,
            _state: &Value,
        ) -> Result<VerifiedCredential, AuthError> {
            Ok(VerifiedCredential {
                credential_id: vec![7; 32],
                public_data: serde_json::json!({"public": true}),
            })
        }

        fn start_authentication(&self) -> Result<(Value, Value), AuthError> {
            Ok((serde_json::json!({"challenge": "login"}), json_state()))
        }

        fn authentication_user_handle(&self, response: &Value) -> Result<Uuid, AuthError> {
            response["handle"]
                .as_str()
                .ok_or(AuthError::InvalidInput)?
                .parse()
                .map_err(|_| AuthError::InvalidInput)
        }

        fn finish_authentication(
            &self,
            _response: &Value,
            _state: &Value,
            credentials: &[StoredCredential],
        ) -> Result<AuthenticationVerification, AuthError> {
            let credential = credentials.first().ok_or(AuthError::Verification)?;
            Ok(AuthenticationVerification {
                credential_id: credential.credential_id.clone(),
                updated_public_data: credential.public_data.clone(),
            })
        }
    }

    fn json_state() -> Value {
        serde_json::json!({"server_state": "opaque"})
    }

    struct FakeState {
        users: HashMap<String, User>,
        capabilities: HashMap<SecretHash, Capability>,
        ceremonies: HashMap<Uuid, Ceremony>,
        credentials: Vec<StoredCredential>,
        sessions: HashMap<SecretHash, SessionRecord>,
        recoveries: HashMap<Uuid, RecoveryRequest>,
    }

    struct FakeStore(Mutex<FakeState>);

    impl FakeStore {
        fn new(user: User) -> Self {
            let mut users = HashMap::new();
            users.insert(user.id.as_str().to_owned(), user);
            Self(Mutex::new(FakeState {
                users,
                capabilities: HashMap::new(),
                ceremonies: HashMap::new(),
                credentials: Vec::new(),
                sessions: HashMap::new(),
                recoveries: HashMap::new(),
            }))
        }
    }

    #[async_trait]
    impl AuthStore for FakeStore {
        async fn user_by_id(&self, id: &UserId) -> Result<Option<User>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state.users.get(id.as_str()).cloned())
        }

        async fn user_by_handle(&self, handle: Uuid) -> Result<Option<User>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state
                .users
                .values()
                .find(|user| user.webauthn_handle == handle)
                .cloned())
        }

        async fn credentials_for_user(
            &self,
            user_id: &UserId,
        ) -> Result<Vec<StoredCredential>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state
                .credentials
                .iter()
                .filter(|credential| credential.user_id == *user_id)
                .cloned()
                .collect())
        }

        async fn operator_without_credential(&self) -> Result<Option<User>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            let has_operator_credential = state.credentials.iter().any(|credential| {
                state
                    .users
                    .get(credential.user_id.as_str())
                    .is_some_and(|user| user.role == Role::Operator)
                    && credential.revoked_at.is_none()
            });
            if has_operator_credential {
                return Ok(None);
            }
            Ok(state
                .users
                .values()
                .find(|user| user.role == Role::Operator && user.enabled)
                .cloned())
        }

        async fn operator_exists(&self) -> Result<bool, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state.users.values().any(|user| user.role == Role::Operator))
        }

        async fn operator_recovery_window(
            &self,
            now: DateTime<Utc>,
        ) -> Result<Option<(User, SecretHash)>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state
                .capabilities
                .values()
                .find(|capability| {
                    capability.purpose == CapabilityPurpose::OperatorRecovery
                        && capability.expires_at > now
                })
                .and_then(|capability| {
                    state
                        .users
                        .get(capability.user_id.as_str())
                        .cloned()
                        .map(|user| (user, capability.token_hash))
                }))
        }

        async fn capability(
            &self,
            hash: SecretHash,
            purpose: CapabilityPurpose,
            now: DateTime<Utc>,
        ) -> Result<Option<Capability>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state
                .capabilities
                .get(&hash)
                .filter(|capability| capability.purpose == purpose && capability.expires_at > now)
                .cloned())
        }

        async fn insert_capability(&self, capability: Capability) -> Result<(), AuthError> {
            self.0
                .lock()
                .map_err(|_| AuthError::Store)?
                .capabilities
                .insert(capability.token_hash, capability);
            Ok(())
        }

        async fn insert_user(
            &self,
            user: User,
            _now: DateTime<Utc>,
            _audit: AuditEvent,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            if state.users.contains_key(user.id.as_str()) {
                return Err(AuthError::Conflict);
            }
            state.users.insert(user.id.as_str().to_owned(), user);
            Ok(())
        }

        async fn approve_user_with_setup(
            &self,
            user: User,
            capability: Capability,
            _operator_id: &UserId,
            _now: DateTime<Utc>,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            if state.users.contains_key(user.id.as_str()) {
                return Err(AuthError::Conflict);
            }
            state.users.insert(user.id.as_str().to_owned(), user);
            state.capabilities.insert(capability.token_hash, capability);
            Ok(())
        }

        async fn rotate_all_auth_epochs(
            &self,
            _now: DateTime<Utc>,
            _reason: &str,
        ) -> Result<u64, AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let count = state.users.len() as u64;
            for user in state.users.values_mut() {
                user.auth_epoch += 1;
            }
            state.sessions.clear();
            state.ceremonies.clear();
            state.capabilities.clear();
            Ok(count)
        }

        async fn insert_ceremony(&self, ceremony: Ceremony) -> Result<(), AuthError> {
            self.0
                .lock()
                .map_err(|_| AuthError::Store)?
                .ceremonies
                .insert(ceremony.id, ceremony);
            Ok(())
        }

        async fn ceremony(
            &self,
            id: Uuid,
            kind: CeremonyKind,
            now: DateTime<Utc>,
        ) -> Result<Option<Ceremony>, AuthError> {
            let state = self.0.lock().map_err(|_| AuthError::Store)?;
            Ok(state
                .ceremonies
                .get(&id)
                .filter(|ceremony| ceremony.kind == kind && ceremony.expires_at > now)
                .cloned())
        }

        async fn complete_registration(
            &self,
            ceremony_id: Uuid,
            capability_hash: Option<SecretHash>,
            credential: VerifiedCredential,
            now: DateTime<Utc>,
            _audit: AuditEvent,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let ceremony = state
                .ceremonies
                .remove(&ceremony_id)
                .filter(|ceremony| ceremony.expires_at > now)
                .ok_or(AuthError::InvalidState)?;
            if let Some(hash) = capability_hash {
                state
                    .capabilities
                    .remove(&hash)
                    .ok_or(AuthError::InvalidState)?;
            }
            state.credentials.push(StoredCredential {
                id: Uuid::new_v4(),
                user_id: ceremony.user_id.ok_or(AuthError::InvalidState)?,
                credential_id: credential.credential_id,
                public_data: credential.public_data,
                revoked_at: None,
            });
            Ok(())
        }

        async fn complete_authentication(
            &self,
            ceremony_id: Uuid,
            _verification: AuthenticationVerification,
            session: SessionRecord,
            now: DateTime<Utc>,
            _audit: AuditEvent,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            state
                .ceremonies
                .remove(&ceremony_id)
                .filter(|ceremony| ceremony.expires_at > now)
                .ok_or(AuthError::InvalidState)?;
            state.sessions.insert(session.token_hash, session);
            Ok(())
        }

        async fn session(
            &self,
            token_hash: SecretHash,
            now: DateTime<Utc>,
            idle_expires_at: DateTime<Utc>,
        ) -> Result<Option<SessionPrincipal>, AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let Some(session) = state.sessions.get(&token_hash).cloned() else {
                return Ok(None);
            };
            let Some(user) = state.users.get(session.user_id.as_str()).cloned() else {
                return Ok(None);
            };
            let Some(session) = state.sessions.get_mut(&token_hash) else {
                return Ok(None);
            };
            if session.idle_expires_at <= now
                || session.absolute_expires_at <= now
                || session.auth_epoch != user.auth_epoch
            {
                return Ok(None);
            }
            session.idle_expires_at = idle_expires_at.min(session.absolute_expires_at);
            Ok(Some(SessionPrincipal {
                session_id: session.id,
                user,
                csrf_hash: session.csrf_hash,
                absolute_expires_at: session.absolute_expires_at,
            }))
        }

        async fn rotate_session_csrf(
            &self,
            token_hash: SecretHash,
            csrf_hash: SecretHash,
            now: DateTime<Utc>,
            idle_expires_at: DateTime<Utc>,
        ) -> Result<Option<SessionPrincipal>, AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let Some(session) = state.sessions.get(&token_hash).cloned() else {
                return Ok(None);
            };
            let Some(user) = state.users.get(session.user_id.as_str()).cloned() else {
                return Ok(None);
            };
            let Some(session) = state.sessions.get_mut(&token_hash) else {
                return Ok(None);
            };
            if session.idle_expires_at <= now
                || session.absolute_expires_at <= now
                || session.auth_epoch != user.auth_epoch
            {
                return Ok(None);
            }
            session.csrf_hash = csrf_hash;
            session.idle_expires_at = idle_expires_at.min(session.absolute_expires_at);
            Ok(Some(SessionPrincipal {
                session_id: session.id,
                user,
                csrf_hash,
                absolute_expires_at: session.absolute_expires_at,
            }))
        }

        async fn delete_session(&self, token_hash: SecretHash) -> Result<(), AuthError> {
            self.0
                .lock()
                .map_err(|_| AuthError::Store)?
                .sessions
                .remove(&token_hash);
            Ok(())
        }

        async fn create_recovery(
            &self,
            user_id: &UserId,
            now: DateTime<Utc>,
        ) -> Result<RecoveryRequest, AuthError> {
            let request = RecoveryRequest {
                id: Uuid::new_v4(),
                user_id: user_id.clone(),
                requested_at: now,
                approved_at: None,
            };
            self.0
                .lock()
                .map_err(|_| AuthError::Store)?
                .recoveries
                .insert(request.id, request.clone());
            Ok(request)
        }

        async fn pending_recoveries(&self) -> Result<Vec<RecoveryRequest>, AuthError> {
            Ok(self
                .0
                .lock()
                .map_err(|_| AuthError::Store)?
                .recoveries
                .values()
                .cloned()
                .collect())
        }

        async fn approve_recovery(
            &self,
            recovery_id: Uuid,
            _operator_id: &UserId,
            now: DateTime<Utc>,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let recovery = state
                .recoveries
                .get_mut(&recovery_id)
                .ok_or(AuthError::Conflict)?;
            recovery.approved_at = Some(now);
            let user_id = recovery.user_id.as_str().to_owned();
            if let Some(user) = state.users.get_mut(&user_id) {
                user.auth_epoch += 1;
            }
            state
                .sessions
                .retain(|_, session| session.user_id.as_str() != user_id);
            state.ceremonies.retain(|_, ceremony| {
                ceremony
                    .user_id
                    .as_ref()
                    .is_none_or(|id| id.as_str() != user_id)
            });
            state
                .capabilities
                .retain(|_, capability| capability.user_id.as_str() != user_id);
            Ok(())
        }

        async fn issue_recovery_setup(
            &self,
            _recovery_id: Uuid,
            capability: Capability,
            _operator_id: &UserId,
            _now: DateTime<Utc>,
        ) -> Result<(), AuthError> {
            self.insert_capability(capability).await
        }

        async fn break_glass(
            &self,
            _credential_id: Uuid,
            capability: Capability,
            _now: DateTime<Utc>,
            _reason: &str,
        ) -> Result<(), AuthError> {
            let mut state = self.0.lock().map_err(|_| AuthError::Store)?;
            let user_id = capability.user_id.as_str().to_owned();
            if let Some(user) = state.users.get_mut(&user_id) {
                user.auth_epoch += 1;
            }
            state
                .sessions
                .retain(|_, session| session.user_id.as_str() != user_id);
            state.ceremonies.retain(|_, ceremony| {
                ceremony
                    .user_id
                    .as_ref()
                    .is_none_or(|id| id.as_str() != user_id)
            });
            state
                .capabilities
                .retain(|_, existing| existing.user_id.as_str() != user_id);
            state.capabilities.insert(capability.token_hash, capability);
            Ok(())
        }
    }

    fn test_user() -> User {
        User {
            id: UserId::new("user-1").expect("valid ID"),
            webauthn_handle: Uuid::new_v4(),
            email: "user@example.test".to_owned(),
            display_name: "Test User".to_owned(),
            role: Role::User,
            enabled: true,
            auth_epoch: 1,
        }
    }

    fn service(store: Arc<FakeStore>) -> AuthService<FakeStore, FakeEngine> {
        AuthService::new(store, Arc::new(FakeEngine), AuthConfig::default())
    }

    #[test]
    fn tokens_are_256_bit_url_safe_values_and_hashes_hide_plaintext() {
        let token = SecretToken::generate();
        let encoded = token.expose();
        let parsed = SecretToken::parse(&encoded).expect("token parses");

        assert_eq!(encoded.len(), 43);
        assert_eq!(parsed.hash(), token.hash());
        assert!(!format!("{:?}", token.hash()).contains(&encoded));
        assert_ne!(token.hash().as_bytes(), encoded.as_bytes());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        assert!(matches!(
            SecretToken::parse("short"),
            Err(AuthError::InvalidToken)
        ));
        assert!(matches!(
            SecretToken::parse("not+url/safe"),
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn registration_state_and_capability_are_one_use_and_expire() {
        let now = Utc::now();
        let user = test_user();
        let store = Arc::new(FakeStore::new(user.clone()));
        let service = service(Arc::clone(&store));
        let setup = SecretToken::generate();
        store
            .insert_capability(Capability {
                id: Uuid::new_v4(),
                user_id: user.id,
                purpose: CapabilityPurpose::Setup,
                token_hash: setup.hash(),
                expires_at: now + Duration::minutes(1),
            })
            .await
            .expect("capability inserts");
        let (ceremony_id, _) = service
            .start_setup_registration(&setup, CapabilityPurpose::Setup, now)
            .await
            .expect("registration starts");
        service
            .finish_registration(ceremony_id, CeremonyKind::Registration, &Value::Null, now)
            .await
            .expect("registration finishes once");
        assert!(matches!(
            service
                .finish_registration(ceremony_id, CeremonyKind::Registration, &Value::Null, now,)
                .await,
            Err(AuthError::InvalidState)
        ));
        assert!(matches!(
            service
                .start_setup_registration(
                    &setup,
                    CapabilityPurpose::Setup,
                    now + Duration::minutes(2),
                )
                .await,
            Err(AuthError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn logout_and_epoch_change_revoke_sessions() {
        let now = Utc::now();
        let user = test_user();
        let handle = user.webauthn_handle;
        let store = Arc::new(FakeStore::new(user.clone()));
        store
            .0
            .lock()
            .expect("lock")
            .credentials
            .push(StoredCredential {
                id: Uuid::new_v4(),
                user_id: user.id.clone(),
                credential_id: vec![3; 32],
                public_data: json_state(),
                revoked_at: None,
            });
        let service = service(Arc::clone(&store));
        let (ceremony_id, _) = service
            .start_authentication(now)
            .await
            .expect("login starts");
        let (grant, _) = service
            .finish_authentication(ceremony_id, &serde_json::json!({"handle": handle}), now)
            .await
            .expect("login finishes");
        service
            .authenticate_session(&grant.token, Some(&grant.csrf), now)
            .await
            .expect("session authenticates");
        service.logout(&grant.token).await.expect("logout succeeds");
        assert!(matches!(
            service.authenticate_session(&grant.token, None, now).await,
            Err(AuthError::Unauthenticated)
        ));

        let (ceremony_id, _) = service
            .start_authentication(now)
            .await
            .expect("second login starts");
        let (second, _) = service
            .finish_authentication(ceremony_id, &serde_json::json!({"handle": handle}), now)
            .await
            .expect("second login finishes");
        let recovery = service
            .request_recovery(&user.id, now)
            .await
            .expect("recovery requested");
        service
            .approve_recovery(recovery.id, &user.id, now)
            .await
            .expect("recovery approved");
        assert!(matches!(
            service.authenticate_session(&second.token, None, now).await,
            Err(AuthError::Unauthenticated)
        ));
        let state = store.0.lock().expect("lock");
        assert!(state.ceremonies.is_empty());
        assert!(state.capabilities.is_empty());
    }

    #[tokio::test]
    async fn approved_user_receives_one_use_setup_capability() {
        let now = Utc::now();
        let operator = User {
            id: UserId::new("operator").expect("valid ID"),
            webauthn_handle: Uuid::new_v4(),
            email: "operator@example.test".to_owned(),
            display_name: "Operator".to_owned(),
            role: Role::Operator,
            enabled: true,
            auth_epoch: 1,
        };
        let store = Arc::new(FakeStore::new(operator.clone()));
        let service = service(Arc::clone(&store));
        let token = service
            .approve_user_and_issue_setup(
                &operator.id,
                UserId::new("user-2").expect("valid ID"),
                "user-2@example.test".to_owned(),
                "Approved User".to_owned(),
                now,
            )
            .await
            .expect("approval issues setup");
        let (ceremony_id, _) = service
            .start_setup_registration(&token, CapabilityPurpose::Setup, now)
            .await
            .expect("setup starts");
        service
            .finish_registration(ceremony_id, CeremonyKind::Registration, &Value::Null, now)
            .await
            .expect("setup finishes");
        assert!(matches!(
            service
                .start_setup_registration(&token, CapabilityPurpose::Setup, now)
                .await,
            Err(AuthError::InvalidToken)
        ));
    }
}
