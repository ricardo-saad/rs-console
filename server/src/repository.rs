use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rs_console_auth::{
    AuditEvent, AuthError, AuthStore, AuthenticationVerification, Capability, CapabilityPurpose,
    Ceremony, CeremonyKind, RecoveryRequest, Role, SecretHash, SessionPrincipal, SessionRecord,
    StoredCredential, User, VerifiedCredential,
};
use rs_console_policy::UserId;
use serde_json::Value;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone)]
pub struct PgAuthStore {
    pool: PgPool,
}

impl PgAuthStore {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("./migrations").run(&self.pool).await
    }

    pub async fn ready(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }
}

#[derive(FromRow)]
struct UserRow {
    id: String,
    webauthn_handle: Uuid,
    email: String,
    display_name: String,
    role: String,
    enabled: bool,
    auth_epoch: i64,
}

impl TryFrom<UserRow> for User {
    type Error = AuthError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: UserId::new(row.id).map_err(|_| AuthError::Store)?,
            webauthn_handle: row.webauthn_handle,
            email: row.email,
            display_name: row.display_name,
            role: parse_role(&row.role)?,
            enabled: row.enabled,
            auth_epoch: row.auth_epoch,
        })
    }
}

#[derive(FromRow)]
struct CredentialRow {
    id: Uuid,
    user_id: String,
    credential_id: Vec<u8>,
    public_data: Value,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<CredentialRow> for StoredCredential {
    type Error = AuthError;

    fn try_from(row: CredentialRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            user_id: UserId::new(row.user_id).map_err(|_| AuthError::Store)?,
            credential_id: row.credential_id,
            public_data: row.public_data,
            revoked_at: row.revoked_at,
        })
    }
}

#[derive(FromRow)]
struct CapabilityRow {
    id: Uuid,
    user_id: String,
    purpose: String,
    token_hash: Vec<u8>,
    expires_at: DateTime<Utc>,
}

impl TryFrom<CapabilityRow> for Capability {
    type Error = AuthError;

    fn try_from(row: CapabilityRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            user_id: UserId::new(row.user_id).map_err(|_| AuthError::Store)?,
            purpose: parse_purpose(&row.purpose)?,
            token_hash: SecretHash::from_slice(&row.token_hash)?,
            expires_at: row.expires_at,
        })
    }
}

#[derive(FromRow)]
struct CeremonyRow {
    id: Uuid,
    kind: String,
    user_id: Option<String>,
    capability_hash: Option<Vec<u8>>,
    state: Value,
    expires_at: DateTime<Utc>,
}

impl TryFrom<CeremonyRow> for Ceremony {
    type Error = AuthError;

    fn try_from(row: CeremonyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            kind: parse_ceremony_kind(&row.kind)?,
            user_id: row
                .user_id
                .map(UserId::new)
                .transpose()
                .map_err(|_| AuthError::Store)?,
            capability_hash: row
                .capability_hash
                .map(|hash| SecretHash::from_slice(&hash))
                .transpose()?,
            state: row.state,
            expires_at: row.expires_at,
        })
    }
}

#[derive(FromRow)]
struct RecoveryRow {
    id: Uuid,
    user_id: String,
    requested_at: DateTime<Utc>,
    approved_at: Option<DateTime<Utc>>,
}

impl TryFrom<RecoveryRow> for RecoveryRequest {
    type Error = AuthError;

    fn try_from(row: RecoveryRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            user_id: UserId::new(row.user_id).map_err(|_| AuthError::Store)?,
            requested_at: row.requested_at,
            approved_at: row.approved_at,
        })
    }
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Operator => "operator",
    }
}

fn parse_role(role: &str) -> Result<Role, AuthError> {
    match role {
        "user" => Ok(Role::User),
        "operator" => Ok(Role::Operator),
        _ => Err(AuthError::Store),
    }
}

fn purpose_name(purpose: CapabilityPurpose) -> &'static str {
    match purpose {
        CapabilityPurpose::Setup => "setup",
        CapabilityPurpose::RecoverySetup => "recovery_setup",
        CapabilityPurpose::OperatorRecovery => "operator_recovery",
    }
}

fn parse_purpose(value: &str) -> Result<CapabilityPurpose, AuthError> {
    match value {
        "setup" => Ok(CapabilityPurpose::Setup),
        "recovery_setup" => Ok(CapabilityPurpose::RecoverySetup),
        "operator_recovery" => Ok(CapabilityPurpose::OperatorRecovery),
        _ => Err(AuthError::Store),
    }
}

fn ceremony_name(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::Registration => "registration",
        CeremonyKind::Authentication => "authentication",
        CeremonyKind::OperatorBootstrap => "operator_bootstrap",
        CeremonyKind::OperatorRecovery => "operator_recovery",
    }
}

fn parse_ceremony_kind(value: &str) -> Result<CeremonyKind, AuthError> {
    match value {
        "registration" => Ok(CeremonyKind::Registration),
        "authentication" => Ok(CeremonyKind::Authentication),
        "operator_bootstrap" => Ok(CeremonyKind::OperatorBootstrap),
        "operator_recovery" => Ok(CeremonyKind::OperatorRecovery),
        _ => Err(AuthError::Store),
    }
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    event: AuditEvent,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO auth_audit_events
         (occurred_at, event_type, actor_user_id, subject_user_id, data)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(now)
    .bind(event.event_type)
    .bind(event.actor_user_id.map(|id| id.to_string()))
    .bind(event.subject_user_id.map(|id| id.to_string()))
    .bind(event.data)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuthError::Store)?;
    Ok(())
}

#[async_trait]
impl AuthStore for PgAuthStore {
    async fn user_by_id(&self, id: &UserId) -> Result<Option<User>, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, webauthn_handle, email, display_name, role, enabled, auth_epoch
             FROM human_users WHERE id = $1",
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(User::try_from)
        .transpose()
    }

    async fn user_by_handle(&self, handle: Uuid) -> Result<Option<User>, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "SELECT id, webauthn_handle, email, display_name, role, enabled, auth_epoch
             FROM human_users WHERE webauthn_handle = $1",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(User::try_from)
        .transpose()
    }

    async fn credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<StoredCredential>, AuthError> {
        sqlx::query_as::<_, CredentialRow>(
            "SELECT id, user_id, credential_id, public_data, revoked_at
             FROM passkey_credentials
             WHERE user_id = $1 AND revoked_at IS NULL
             ORDER BY created_at",
        )
        .bind(user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .into_iter()
        .map(StoredCredential::try_from)
        .collect()
    }

    async fn operator_without_credential(&self) -> Result<Option<User>, AuthError> {
        sqlx::query_as::<_, UserRow>(
            "SELECT u.id, u.webauthn_handle, u.email, u.display_name, u.role,
                    u.enabled, u.auth_epoch
             FROM human_users u
             WHERE u.role = 'operator' AND u.enabled
               AND NOT EXISTS (
                   SELECT 1
                   FROM passkey_credentials c
                   JOIN human_users existing_operator
                     ON existing_operator.id = c.user_id
                   WHERE existing_operator.role = 'operator'
                     AND c.revoked_at IS NULL
               )
             ORDER BY u.created_at
             LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(User::try_from)
        .transpose()
    }

    async fn operator_exists(&self) -> Result<bool, AuthError> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM human_users WHERE role = 'operator')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::Store)
    }

    async fn operator_recovery_window(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<(User, SecretHash)>, AuthError> {
        #[derive(FromRow)]
        struct Row {
            id: String,
            webauthn_handle: Uuid,
            email: String,
            display_name: String,
            role: String,
            enabled: bool,
            auth_epoch: i64,
            token_hash: Vec<u8>,
        }

        sqlx::query_as::<_, Row>(
            "SELECT u.id, u.webauthn_handle, u.email, u.display_name, u.role,
                    u.enabled, u.auth_epoch, c.token_hash
             FROM auth_capabilities c
             JOIN human_users u ON u.id = c.user_id
             WHERE c.purpose = 'operator_recovery' AND c.consumed_at IS NULL
               AND c.expires_at > $1 AND u.role = 'operator' AND u.enabled
             ORDER BY c.created_at DESC
             LIMIT 1",
        )
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(|row| {
            let hash = SecretHash::from_slice(&row.token_hash)?;
            let user = User::try_from(UserRow {
                id: row.id,
                webauthn_handle: row.webauthn_handle,
                email: row.email,
                display_name: row.display_name,
                role: row.role,
                enabled: row.enabled,
                auth_epoch: row.auth_epoch,
            })?;
            Ok((user, hash))
        })
        .transpose()
    }

    async fn capability(
        &self,
        hash: SecretHash,
        purpose: CapabilityPurpose,
        now: DateTime<Utc>,
    ) -> Result<Option<Capability>, AuthError> {
        sqlx::query_as::<_, CapabilityRow>(
            "SELECT id, user_id, purpose, token_hash, expires_at
             FROM auth_capabilities
             WHERE token_hash = $1 AND purpose = $2 AND consumed_at IS NULL
               AND expires_at > $3",
        )
        .bind(hash.as_bytes().as_slice())
        .bind(purpose_name(purpose))
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(Capability::try_from)
        .transpose()
    }

    async fn insert_capability(&self, capability: Capability) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_capabilities
             (id, user_id, purpose, token_hash, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(capability.id)
        .bind(capability.user_id.as_str())
        .bind(purpose_name(capability.purpose))
        .bind(capability.token_hash.as_bytes().as_slice())
        .bind(capability.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?;
        Ok(())
    }

    async fn insert_user(
        &self,
        user: User,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let result = sqlx::query(
            "INSERT INTO human_users
             (id, webauthn_handle, email, display_name, role, enabled, auth_epoch, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
        )
        .bind(user.id.as_str())
        .bind(user.webauthn_handle)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(role_name(user.role))
        .bind(user.enabled)
        .bind(user.auth_epoch)
        .bind(now)
        .execute(&mut *transaction)
        .await;
        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) if error.constraint().is_some() => {
                return Err(AuthError::Conflict);
            }
            Err(_) => return Err(AuthError::Store),
        }
        insert_audit(&mut transaction, audit, now).await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn approve_user_with_setup(
        &self,
        user: User,
        capability: Capability,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let result = sqlx::query(
            "INSERT INTO human_users
             (id, webauthn_handle, email, display_name, role, enabled, auth_epoch, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
        )
        .bind(user.id.as_str())
        .bind(user.webauthn_handle)
        .bind(&user.email)
        .bind(&user.display_name)
        .bind(role_name(user.role))
        .bind(user.enabled)
        .bind(user.auth_epoch)
        .bind(now)
        .execute(&mut *transaction)
        .await;
        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(error)) if error.constraint().is_some() => {
                return Err(AuthError::Conflict);
            }
            Err(_) => return Err(AuthError::Store),
        }
        sqlx::query(
            "INSERT INTO auth_capabilities
             (id, user_id, purpose, token_hash, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(capability.id)
        .bind(capability.user_id.as_str())
        .bind(purpose_name(capability.purpose))
        .bind(capability.token_hash.as_bytes().as_slice())
        .bind(capability.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        insert_audit(
            &mut transaction,
            AuditEvent {
                event_type: "user.approved_with_setup".to_owned(),
                actor_user_id: Some(operator_id.clone()),
                subject_user_id: Some(user.id),
                data: serde_json::json!({"capability_id": capability.id}),
            },
            now,
        )
        .await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn rotate_all_auth_epochs(
        &self,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<u64, AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let users = sqlx::query_scalar::<_, i64>(
            "UPDATE human_users
             SET auth_epoch = auth_epoch + 1, updated_at = $1
             RETURNING 1",
        )
        .bind(now)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        sqlx::query("UPDATE auth_sessions SET revoked_at = $1 WHERE revoked_at IS NULL")
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
        sqlx::query("UPDATE auth_ceremonies SET consumed_at = $1 WHERE consumed_at IS NULL")
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
        sqlx::query("UPDATE auth_capabilities SET consumed_at = $1 WHERE consumed_at IS NULL")
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
        insert_audit(
            &mut transaction,
            AuditEvent {
                event_type: "auth.epoch_rotated_all".to_owned(),
                actor_user_id: None,
                subject_user_id: None,
                data: serde_json::json!({"reason": reason, "users": users.len()}),
            },
            now,
        )
        .await?;
        transaction.commit().await.map_err(|_| AuthError::Store)?;
        Ok(users.len() as u64)
    }

    async fn insert_ceremony(&self, ceremony: Ceremony) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_ceremonies
             (id, kind, user_id, capability_hash, state, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ceremony.id)
        .bind(ceremony_name(ceremony.kind))
        .bind(ceremony.user_id.map(|id| id.to_string()))
        .bind(
            ceremony
                .capability_hash
                .map(|hash| hash.as_bytes().to_vec()),
        )
        .bind(ceremony.state)
        .bind(ceremony.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?;
        Ok(())
    }

    async fn ceremony(
        &self,
        id: Uuid,
        kind: CeremonyKind,
        now: DateTime<Utc>,
    ) -> Result<Option<Ceremony>, AuthError> {
        sqlx::query_as::<_, CeremonyRow>(
            "SELECT id, kind, user_id, capability_hash, state, expires_at
             FROM auth_ceremonies
             WHERE id = $1 AND kind = $2 AND consumed_at IS NULL AND expires_at > $3",
        )
        .bind(id)
        .bind(ceremony_name(kind))
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .map(Ceremony::try_from)
        .transpose()
    }

    async fn complete_registration(
        &self,
        ceremony_id: Uuid,
        capability_hash: Option<SecretHash>,
        credential: VerifiedCredential,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('rs-console-operator-bootstrap'))")
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
        let (user_id, ceremony_kind) = sqlx::query_as::<_, (String, String)>(
            "UPDATE auth_ceremonies
             SET consumed_at = $2
             WHERE id = $1 AND consumed_at IS NULL AND expires_at > $2
             RETURNING user_id, kind",
        )
        .bind(ceremony_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?
        .ok_or(AuthError::InvalidState)?;

        if ceremony_kind == "operator_bootstrap" {
            let operator_credentials = sqlx::query_scalar::<_, i64>(
                "SELECT count(*)
                 FROM passkey_credentials c
                 JOIN human_users u ON u.id = c.user_id
                 WHERE u.role = 'operator' AND c.revoked_at IS NULL",
            )
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
            if operator_credentials != 0 {
                return Err(AuthError::Conflict);
            }
        }

        if let Some(hash) = capability_hash {
            let consumed = sqlx::query(
                "UPDATE auth_capabilities SET consumed_at = $2
                 WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
            )
            .bind(hash.as_bytes().as_slice())
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(|_| AuthError::Store)?;
            if consumed.rows_affected() != 1 {
                return Err(AuthError::InvalidState);
            }
        }

        sqlx::query(
            "INSERT INTO passkey_credentials
             (id, user_id, credential_id, public_data, created_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(credential.credential_id)
        .bind(credential.public_data)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                AuthError::Conflict
            } else {
                AuthError::Store
            }
        })?;
        sqlx::query(
            "UPDATE recovery_requests
             SET completed_at = $2
             WHERE user_id = $1 AND approved_at IS NOT NULL
               AND setup_issued_at IS NOT NULL AND completed_at IS NULL",
        )
        .bind(audit.subject_user_id.as_ref().map(ToString::to_string))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        insert_audit(&mut transaction, audit, now).await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn complete_authentication(
        &self,
        ceremony_id: Uuid,
        verification: AuthenticationVerification,
        session: SessionRecord,
        now: DateTime<Utc>,
        audit: AuditEvent,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let consumed = sqlx::query(
            "UPDATE auth_ceremonies SET consumed_at = $2
             WHERE id = $1 AND kind = 'authentication'
               AND consumed_at IS NULL AND expires_at > $2",
        )
        .bind(ceremony_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        if consumed.rows_affected() != 1 {
            return Err(AuthError::InvalidState);
        }

        let credential = sqlx::query(
            "UPDATE passkey_credentials
             SET public_data = $3, last_used_at = $4
             WHERE user_id = $1 AND credential_id = $2 AND revoked_at IS NULL",
        )
        .bind(session.user_id.as_str())
        .bind(verification.credential_id)
        .bind(verification.updated_public_data)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        if credential.rows_affected() != 1 {
            return Err(AuthError::Unauthenticated);
        }

        sqlx::query(
            "INSERT INTO auth_sessions
             (id, user_id, token_hash, csrf_hash, auth_epoch,
              idle_expires_at, absolute_expires_at, created_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)",
        )
        .bind(session.id)
        .bind(session.user_id.as_str())
        .bind(session.token_hash.as_bytes().as_slice())
        .bind(session.csrf_hash.as_bytes().as_slice())
        .bind(session.auth_epoch)
        .bind(session.idle_expires_at)
        .bind(session.absolute_expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        insert_audit(&mut transaction, audit, now).await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn session(
        &self,
        token_hash: SecretHash,
        now: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<Option<SessionPrincipal>, AuthError> {
        #[derive(FromRow)]
        struct SessionRow {
            session_id: Uuid,
            csrf_hash: Vec<u8>,
            absolute_expires_at: DateTime<Utc>,
            id: String,
            webauthn_handle: Uuid,
            email: String,
            display_name: String,
            role: String,
            enabled: bool,
            auth_epoch: i64,
        }

        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT s.id AS session_id, s.csrf_hash, s.absolute_expires_at,
                    u.id, u.webauthn_handle, u.email, u.display_name, u.role,
                    u.enabled, u.auth_epoch
             FROM auth_sessions s
             JOIN human_users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.revoked_at IS NULL
               AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2
               AND u.enabled AND s.auth_epoch = u.auth_epoch
             FOR UPDATE OF s",
        )
        .bind(token_hash.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(|_| AuthError::Store)?;
            return Ok(None);
        };
        let bounded_idle = idle_expires_at.min(row.absolute_expires_at);
        sqlx::query(
            "UPDATE auth_sessions
             SET idle_expires_at = $2, last_seen_at = $3
             WHERE id = $1",
        )
        .bind(row.session_id)
        .bind(bounded_idle)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        transaction.commit().await.map_err(|_| AuthError::Store)?;

        Ok(Some(SessionPrincipal {
            session_id: row.session_id,
            user: User::try_from(UserRow {
                id: row.id,
                webauthn_handle: row.webauthn_handle,
                email: row.email,
                display_name: row.display_name,
                role: row.role,
                enabled: row.enabled,
                auth_epoch: row.auth_epoch,
            })?,
            csrf_hash: SecretHash::from_slice(&row.csrf_hash)?,
            absolute_expires_at: row.absolute_expires_at,
        }))
    }

    async fn rotate_session_csrf(
        &self,
        token_hash: SecretHash,
        csrf_hash: SecretHash,
        now: DateTime<Utc>,
        idle_expires_at: DateTime<Utc>,
    ) -> Result<Option<SessionPrincipal>, AuthError> {
        #[derive(FromRow)]
        struct SessionRow {
            session_id: Uuid,
            absolute_expires_at: DateTime<Utc>,
            id: String,
            webauthn_handle: Uuid,
            email: String,
            display_name: String,
            role: String,
            enabled: bool,
            auth_epoch: i64,
        }

        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let row = sqlx::query_as::<_, SessionRow>(
            "SELECT s.id AS session_id, s.absolute_expires_at,
                    u.id, u.webauthn_handle, u.email, u.display_name, u.role,
                    u.enabled, u.auth_epoch
             FROM auth_sessions s
             JOIN human_users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.revoked_at IS NULL
               AND s.idle_expires_at > $2 AND s.absolute_expires_at > $2
               AND u.enabled AND s.auth_epoch = u.auth_epoch
             FOR UPDATE OF s",
        )
        .bind(token_hash.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(|_| AuthError::Store)?;
            return Ok(None);
        };
        let bounded_idle = idle_expires_at.min(row.absolute_expires_at);
        sqlx::query(
            "UPDATE auth_sessions
             SET csrf_hash = $2, idle_expires_at = $3, last_seen_at = $4
             WHERE id = $1",
        )
        .bind(row.session_id)
        .bind(csrf_hash.as_bytes().as_slice())
        .bind(bounded_idle)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        transaction.commit().await.map_err(|_| AuthError::Store)?;

        Ok(Some(SessionPrincipal {
            session_id: row.session_id,
            user: User::try_from(UserRow {
                id: row.id,
                webauthn_handle: row.webauthn_handle,
                email: row.email,
                display_name: row.display_name,
                role: row.role,
                enabled: row.enabled,
                auth_epoch: row.auth_epoch,
            })?,
            csrf_hash,
            absolute_expires_at: row.absolute_expires_at,
        }))
    }

    async fn delete_session(&self, token_hash: SecretHash) -> Result<(), AuthError> {
        sqlx::query(
            "UPDATE auth_sessions SET revoked_at = now()
             WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash.as_bytes().as_slice())
        .execute(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?;
        Ok(())
    }

    async fn create_recovery(
        &self,
        user_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<RecoveryRequest, AuthError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO recovery_requests (id, user_id, requested_at)
             VALUES ($1, $2, $3)",
        )
        .bind(id)
        .bind(user_id.as_str())
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
            {
                AuthError::Conflict
            } else {
                AuthError::Store
            }
        })?;
        Ok(RecoveryRequest {
            id,
            user_id: user_id.clone(),
            requested_at: now,
            approved_at: None,
        })
    }

    async fn pending_recoveries(&self) -> Result<Vec<RecoveryRequest>, AuthError> {
        sqlx::query_as::<_, RecoveryRow>(
            "SELECT id, user_id, requested_at, approved_at
             FROM recovery_requests
             WHERE completed_at IS NULL
             ORDER BY requested_at",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AuthError::Store)?
        .into_iter()
        .map(RecoveryRequest::try_from)
        .collect()
    }

    async fn approve_recovery(
        &self,
        recovery_id: Uuid,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let user_id = sqlx::query_scalar::<_, String>(
            "UPDATE recovery_requests
             SET approved_at = $2, approved_by = $3
             WHERE id = $1 AND approved_at IS NULL AND completed_at IS NULL
             RETURNING user_id",
        )
        .bind(recovery_id)
        .bind(now)
        .bind(operator_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?
        .ok_or(AuthError::Conflict)?;
        invalidate_user_auth(&mut transaction, &user_id, now).await?;
        insert_audit(
            &mut transaction,
            AuditEvent {
                event_type: "recovery.approved".to_owned(),
                actor_user_id: Some(operator_id.clone()),
                subject_user_id: Some(UserId::new(user_id).map_err(|_| AuthError::Store)?),
                data: serde_json::json!({"recovery_id": recovery_id}),
            },
            now,
        )
        .await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn issue_recovery_setup(
        &self,
        recovery_id: Uuid,
        capability: Capability,
        operator_id: &UserId,
        now: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let issued = sqlx::query(
            "UPDATE recovery_requests SET setup_issued_at = $2
             WHERE id = $1 AND approved_at IS NOT NULL
               AND setup_issued_at IS NULL AND completed_at IS NULL
               AND user_id = $3",
        )
        .bind(recovery_id)
        .bind(now)
        .bind(capability.user_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        if issued.rows_affected() != 1 {
            return Err(AuthError::Conflict);
        }
        sqlx::query(
            "INSERT INTO auth_capabilities
             (id, user_id, purpose, token_hash, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(capability.id)
        .bind(capability.user_id.as_str())
        .bind(purpose_name(capability.purpose))
        .bind(capability.token_hash.as_bytes().as_slice())
        .bind(capability.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        insert_audit(
            &mut transaction,
            AuditEvent {
                event_type: "recovery.setup_issued".to_owned(),
                actor_user_id: Some(operator_id.clone()),
                subject_user_id: Some(capability.user_id),
                data: serde_json::json!({"recovery_id": recovery_id}),
            },
            now,
        )
        .await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }

    async fn break_glass(
        &self,
        credential_id: Uuid,
        capability: Capability,
        now: DateTime<Utc>,
        reason: &str,
    ) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(|_| AuthError::Store)?;
        let user_id = sqlx::query_scalar::<_, String>(
            "UPDATE passkey_credentials c
             SET revoked_at = $2
             FROM human_users u
             WHERE c.id = $1 AND c.user_id = u.id AND u.role = 'operator'
               AND c.revoked_at IS NULL
             RETURNING c.user_id",
        )
        .bind(credential_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?
        .ok_or(AuthError::Conflict)?;
        if capability.user_id.as_str() != user_id {
            return Err(AuthError::Forbidden);
        }
        invalidate_user_auth(&mut transaction, &user_id, now).await?;
        sqlx::query(
            "INSERT INTO auth_capabilities
             (id, user_id, purpose, token_hash, expires_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(capability.id)
        .bind(capability.user_id.as_str())
        .bind(purpose_name(capability.purpose))
        .bind(capability.token_hash.as_bytes().as_slice())
        .bind(capability.expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| AuthError::Store)?;
        insert_audit(
            &mut transaction,
            AuditEvent {
                event_type: "operator.break_glass_opened".to_owned(),
                actor_user_id: None,
                subject_user_id: Some(capability.user_id),
                data: serde_json::json!({
                    "credential_id": credential_id,
                    "reason": reason,
                }),
            },
            now,
        )
        .await?;
        transaction.commit().await.map_err(|_| AuthError::Store)
    }
}

async fn invalidate_user_auth(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE human_users
         SET auth_epoch = auth_epoch + 1, updated_at = $2
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuthError::Store)?;
    sqlx::query(
        "UPDATE auth_sessions SET revoked_at = $2
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuthError::Store)?;
    sqlx::query(
        "UPDATE auth_ceremonies SET consumed_at = $2
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuthError::Store)?;
    sqlx::query(
        "UPDATE auth_capabilities SET consumed_at = $2
         WHERE user_id = $1 AND consumed_at IS NULL",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|_| AuthError::Store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_database_values_are_exact_and_closed() {
        assert_eq!(role_name(Role::Operator), "operator");
        assert!(parse_role("admin").is_err());
        assert_eq!(
            ceremony_name(CeremonyKind::Authentication),
            "authentication"
        );
        assert!(parse_purpose("email_login").is_err());
    }

    #[test]
    fn migration_stores_only_hashes_and_enforces_append_only_audit() {
        let migration = include_str!("../migrations/0001_human_auth.sql");
        assert!(migration.contains("token_hash bytea"));
        assert!(migration.contains("csrf_hash bytea"));
        assert!(!migration.contains("session_token text"));
        assert!(!migration.contains("setup_token text"));
        assert!(!migration.contains("recovery_token text"));
        assert!(migration.contains("auth_audit_events_append_only"));
    }

    #[test]
    fn recovery_invalidation_covers_all_ephemeral_authority() {
        let source = include_str!("repository.rs");
        assert!(source.contains("SET auth_epoch = auth_epoch + 1"));
        assert!(source.contains("UPDATE auth_sessions SET revoked_at"));
        assert!(source.contains("UPDATE auth_ceremonies SET consumed_at"));
        assert!(source.contains("UPDATE auth_capabilities SET consumed_at"));
        assert!(source.contains("auth.epoch_rotated_all"));
        assert!(source.contains("user.approved_with_setup"));
    }
}
