CREATE TABLE human_users (
    id text PRIMARY KEY,
    webauthn_handle uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    display_name text NOT NULL,
    role text NOT NULL CHECK (role IN ('user', 'operator')),
    enabled boolean NOT NULL DEFAULT true,
    auth_epoch bigint NOT NULL DEFAULT 1 CHECK (auth_epoch > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE passkey_credentials (
    id uuid PRIMARY KEY,
    user_id text NOT NULL REFERENCES human_users(id),
    credential_id bytea NOT NULL UNIQUE,
    public_data jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at timestamptz
);

CREATE TABLE auth_capabilities (
    id uuid PRIMARY KEY,
    user_id text NOT NULL REFERENCES human_users(id),
    purpose text NOT NULL CHECK (purpose IN ('setup', 'recovery_setup', 'operator_recovery')),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_ceremonies (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (
        kind IN ('registration', 'authentication', 'operator_bootstrap', 'operator_recovery')
    ),
    user_id text REFERENCES human_users(id),
    capability_hash bytea CHECK (
        capability_hash IS NULL OR octet_length(capability_hash) = 32
    ),
    state jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE auth_sessions (
    id uuid PRIMARY KEY,
    user_id text NOT NULL REFERENCES human_users(id),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    auth_epoch bigint NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE TABLE recovery_requests (
    id uuid PRIMARY KEY,
    user_id text NOT NULL REFERENCES human_users(id),
    requested_at timestamptz NOT NULL,
    approved_at timestamptz,
    approved_by text REFERENCES human_users(id),
    setup_issued_at timestamptz,
    completed_at timestamptz
);

CREATE UNIQUE INDEX one_pending_recovery_per_user
    ON recovery_requests(user_id)
    WHERE approved_at IS NULL AND completed_at IS NULL;

CREATE TABLE auth_audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    event_type text NOT NULL,
    actor_user_id text REFERENCES human_users(id),
    subject_user_id text REFERENCES human_users(id),
    data jsonb NOT NULL
);

CREATE FUNCTION reject_auth_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'auth audit events are append-only';
END;
$$;

CREATE TRIGGER auth_audit_events_append_only
    BEFORE UPDATE OR DELETE ON auth_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_auth_audit_mutation();

CREATE INDEX active_sessions_by_user ON auth_sessions(user_id)
    WHERE revoked_at IS NULL;
CREATE INDEX active_ceremonies_by_user ON auth_ceremonies(user_id)
    WHERE consumed_at IS NULL;
