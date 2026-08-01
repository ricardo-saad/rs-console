use rs_console_auth::{
    AuthError, AuthenticationVerification, CeremonyEngine, StoredCredential, User,
    VerifiedCredential,
};
use serde_json::Value;
use url::Url;
use webauthn_rs::prelude::{
    DiscoverableAuthentication, DiscoverableKey, Passkey, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

pub const PRODUCTION_RP_ID: &str = "ricardosaad.com";
pub const PRODUCTION_ORIGIN: &str = "https://ricardosaad.com";

pub struct WebauthnEngine {
    webauthn: Webauthn,
}

impl WebauthnEngine {
    pub fn new(rp_id: &str, origin: &str, production: bool) -> Result<Self, AuthError> {
        if production && (rp_id != PRODUCTION_RP_ID || origin != PRODUCTION_ORIGIN) {
            return Err(AuthError::InvalidInput);
        }
        let origin = Url::parse(origin).map_err(|_| AuthError::InvalidInput)?;
        if origin.path() != "/" || origin.query().is_some() || origin.fragment().is_some() {
            return Err(AuthError::InvalidInput);
        }
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .map_err(|_| AuthError::InvalidInput)?
            .rp_name("RS Platform")
            .build()
            .map_err(|_| AuthError::InvalidInput)?;
        Ok(Self { webauthn })
    }
}

impl CeremonyEngine for WebauthnEngine {
    fn start_registration(
        &self,
        user: &User,
        credentials: &[StoredCredential],
    ) -> Result<(Value, Value), AuthError> {
        let exclude = credentials
            .iter()
            .map(stored_passkey)
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .map(|passkey| passkey.cred_id().clone())
            .collect::<Vec<_>>();
        let (challenge, state) = self
            .webauthn
            .start_passkey_registration(
                user.webauthn_handle,
                &user.email,
                &user.display_name,
                (!exclude.is_empty()).then_some(exclude),
            )
            .map_err(|_| AuthError::Verification)?;
        let mut challenge = serde_json::to_value(challenge).map_err(|_| AuthError::Store)?;
        let selection = challenge
            .pointer_mut("/publicKey/authenticatorSelection")
            .and_then(Value::as_object_mut)
            .ok_or(AuthError::Store)?;
        selection.insert(
            "residentKey".to_owned(),
            Value::String("required".to_owned()),
        );
        selection.insert("requireResidentKey".to_owned(), Value::Bool(true));
        Ok((
            challenge,
            serde_json::to_value(state).map_err(|_| AuthError::Store)?,
        ))
    }

    fn finish_registration(
        &self,
        response: &Value,
        state: &Value,
    ) -> Result<VerifiedCredential, AuthError> {
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|_| AuthError::InvalidInput)?;
        let state: PasskeyRegistration =
            serde_json::from_value(state.clone()).map_err(|_| AuthError::InvalidState)?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(|_| AuthError::Verification)?;
        Ok(VerifiedCredential {
            credential_id: passkey.cred_id().as_ref().to_vec(),
            public_data: serde_json::to_value(passkey).map_err(|_| AuthError::Store)?,
        })
    }

    fn start_authentication(&self) -> Result<(Value, Value), AuthError> {
        let (challenge, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| AuthError::Verification)?;
        Ok((
            serde_json::to_value(challenge).map_err(|_| AuthError::Store)?,
            serde_json::to_value(state).map_err(|_| AuthError::Store)?,
        ))
    }

    fn authentication_user_handle(&self, response: &Value) -> Result<uuid::Uuid, AuthError> {
        let response: PublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|_| AuthError::InvalidInput)?;
        self.webauthn
            .identify_discoverable_authentication(&response)
            .map(|(handle, _)| handle)
            .map_err(|_| AuthError::Verification)
    }

    fn finish_authentication(
        &self,
        response: &Value,
        state: &Value,
        credentials: &[StoredCredential],
    ) -> Result<AuthenticationVerification, AuthError> {
        let response: PublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|_| AuthError::InvalidInput)?;
        let state: DiscoverableAuthentication =
            serde_json::from_value(state.clone()).map_err(|_| AuthError::InvalidState)?;
        let mut passkeys = credentials
            .iter()
            .map(stored_passkey)
            .collect::<Result<Vec<_>, _>>()?;
        let discoverable = passkeys
            .iter()
            .map(DiscoverableKey::from)
            .collect::<Vec<_>>();
        let result = self
            .webauthn
            .finish_discoverable_authentication(&response, state, &discoverable)
            .map_err(|_| AuthError::Verification)?;
        let credential_id = result.cred_id().as_ref().to_vec();
        let passkey = passkeys
            .iter_mut()
            .find(|passkey| passkey.cred_id().as_ref() == credential_id)
            .ok_or(AuthError::Verification)?;
        passkey
            .update_credential(&result)
            .ok_or(AuthError::Verification)?;
        Ok(AuthenticationVerification {
            credential_id,
            updated_public_data: serde_json::to_value(passkey).map_err(|_| AuthError::Store)?,
        })
    }
}

fn stored_passkey(credential: &StoredCredential) -> Result<Passkey, AuthError> {
    serde_json::from_value(credential.public_data.clone()).map_err(|_| AuthError::Store)
}

#[cfg(test)]
mod tests {
    use rs_console_auth::Role;
    use rs_console_policy::UserId;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn production_configuration_is_frozen() {
        assert!(WebauthnEngine::new(PRODUCTION_RP_ID, PRODUCTION_ORIGIN, true).is_ok());
        assert!(
            WebauthnEngine::new("platform-api.ricardosaad.com", PRODUCTION_ORIGIN, true).is_err()
        );
        assert!(WebauthnEngine::new(PRODUCTION_RP_ID, "https://evil.example", true).is_err());
    }

    #[test]
    fn origins_cannot_contain_paths_or_wildcards() {
        assert!(WebauthnEngine::new("localhost", "http://localhost:4321/platform", false).is_err());
        assert!(WebauthnEngine::new("localhost", "*", false).is_err());
    }

    #[test]
    fn registration_requires_discoverable_user_verifying_credentials() {
        let engine = WebauthnEngine::new("localhost", "http://localhost:4321", false)
            .expect("development configuration is valid");
        let user = User {
            id: UserId::new("user-1").expect("valid ID"),
            webauthn_handle: Uuid::new_v4(),
            email: "user@example.test".to_owned(),
            display_name: "Test User".to_owned(),
            role: Role::User,
            enabled: true,
            auth_epoch: 1,
        };
        let (challenge, _) = engine
            .start_registration(&user, &[])
            .expect("registration starts");
        assert_eq!(
            challenge.pointer("/publicKey/authenticatorSelection/residentKey"),
            Some(&Value::String("required".to_owned()))
        );
        assert_eq!(
            challenge.pointer("/publicKey/authenticatorSelection/requireResidentKey"),
            Some(&Value::Bool(true))
        );
    }
}
