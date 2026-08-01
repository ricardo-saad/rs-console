use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use rs_console_auth::{
    AuthError, AuthService, CapabilityPurpose, CeremonyKind, Role, SecretToken, SessionPrincipal,
};
use rs_console_policy::UserId;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};
use uuid::Uuid;

use crate::repository::PgAuthStore;
use crate::webauthn::WebauthnEngine;

const SESSION_COOKIE: &str = "__Host-rs_session";
const CSRF_HEADER: &str = "x-csrf-token";

pub struct AppState {
    pub auth: AuthService<PgAuthStore, WebauthnEngine>,
    pub store: Arc<PgAuthStore>,
    pub browser_origin: String,
}

#[derive(Debug)]
struct ApiError(AuthError);

impl From<AuthError> for ApiError {
    fn from(value: AuthError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            AuthError::InvalidInput | AuthError::InvalidToken => StatusCode::BAD_REQUEST,
            AuthError::InvalidState | AuthError::Unauthenticated | AuthError::Verification => {
                StatusCode::UNAUTHORIZED
            }
            AuthError::Forbidden => StatusCode::FORBIDDEN,
            AuthError::Conflict => StatusCode::CONFLICT,
            AuthError::Store => StatusCode::SERVICE_UNAVAILABLE,
        };
        (status, Json(json!({"error": status.canonical_reason()}))).into_response()
    }
}

pub fn public_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/v1/capabilities", get(public_capabilities))
        .route("/v1/session", get(session_discovery))
        .route("/v1/auth/login/start", post(login_start))
        .route("/v1/auth/login/finish", post(login_finish))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/setup/start", post(setup_start))
        .route("/v1/auth/setup/finish", post(setup_finish))
        .route("/v1/recovery/request", post(recovery_request))
        .fallback(not_found)
        .layer(cors(&state.browser_origin))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

pub fn private_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route(
            "/v1/operator/bootstrap/start",
            post(operator_bootstrap_start),
        )
        .route(
            "/v1/operator/bootstrap/finish",
            post(operator_bootstrap_finish),
        )
        .route("/v1/operator/recoveries", get(pending_recoveries))
        .route(
            "/v1/operator/recoveries/{id}/approve",
            post(approve_recovery),
        )
        .route(
            "/v1/operator/recoveries/{id}/setup",
            post(issue_recovery_setup),
        )
        .route("/v1/operator/users", post(approve_user))
        .route("/v1/operator/capabilities", get(operator_capabilities))
        .fallback(not_found)
        .layer(cors(&state.browser_origin))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

fn cors(origin: &str) -> CorsLayer {
    let origin = HeaderValue::from_str(origin).expect("validated origin");
    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin))
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE, HeaderName::from_static(CSRF_HEADER)])
}

async fn no_store(request: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn live() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.store.ready().await {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
    }
}

#[derive(Serialize)]
struct CapabilityDocument {
    schema_version: u8,
    audience: &'static str,
    capabilities: Vec<&'static str>,
}

async fn public_capabilities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CapabilityDocument>, ApiError> {
    let principal = optional_session(&state, &headers).await?;
    Ok(Json(match principal {
        Some(_) => CapabilityDocument {
            schema_version: 1,
            audience: "user",
            capabilities: vec![
                "session.logout",
                "profile.read_self",
                "recovery.request_self",
            ],
        },
        None => CapabilityDocument {
            schema_version: 1,
            audience: "anonymous",
            capabilities: vec![
                "session.discover",
                "auth.login",
                "auth.setup",
                "recovery.request",
            ],
        },
    }))
}

async fn session_discovery(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let Some(value) = cookie_value(&headers, SESSION_COOKIE) else {
        return Ok(Json(json!({"schema_version": 1, "authenticated": false})));
    };
    let token = SecretToken::parse(value)?;
    match state.auth.issue_session_csrf(&token, Utc::now()).await {
        Ok((principal, csrf)) => Ok(Json(json!({
            "schema_version": 1,
            "authenticated": true,
            "principal": {
                "id": principal.user.id,
                "display_name": principal.user.display_name,
                "role": principal.user.role,
            },
            "csrf_token": csrf.expose(),
            "absolute_expires_at": principal.absolute_expires_at,
        }))),
        Err(AuthError::Unauthenticated) => {
            Ok(Json(json!({"schema_version": 1, "authenticated": false})))
        }
        Err(error) => Err(error.into()),
    }
}

async fn login_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    verify_origin_json(&state, &headers)?;
    let (ceremony_id, public_key) = state.auth.start_authentication(Utc::now()).await?;
    Ok(Json(json!({
        "ceremony_id": ceremony_id,
        "public_key": public_key,
    })))
}

#[derive(Deserialize)]
struct CeremonyFinish {
    ceremony_id: Uuid,
    credential: Value,
    #[serde(default)]
    ceremony_kind: Option<CeremonyKind>,
}

async fn login_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CeremonyFinish>,
) -> Result<Response, ApiError> {
    verify_origin_json(&state, &headers)?;
    let (grant, user) = state
        .auth
        .finish_authentication(request.ceremony_id, &request.credential, Utc::now())
        .await?;
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; Secure; HttpOnly; SameSite=Strict",
        grant.token.expose()
    );
    let mut response = Json(json!({
        "schema_version": 1,
        "authenticated": true,
        "role": user.role,
        "csrf_token": grant.csrf.expose(),
        "absolute_expires_at": grant.record.absolute_expires_at,
    }))
    .into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError(AuthError::Store))?,
    );
    Ok(response)
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    verify_origin_json(&state, &headers)?;
    let (token, csrf) = session_and_csrf(&headers)?;
    state
        .auth
        .authenticate_session(&token, Some(&csrf), Utc::now())
        .await?;
    state.auth.logout(&token).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_static(
            "__Host-rs_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    Ok(response)
}

#[derive(Deserialize)]
struct SetupStart {
    setup_token: String,
    #[serde(default)]
    recovery: bool,
}

async fn setup_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<SetupStart>,
) -> Result<Json<Value>, ApiError> {
    verify_origin_json(&state, &headers)?;
    let token = SecretToken::parse(&request.setup_token)?;
    let purpose = if request.recovery {
        CapabilityPurpose::RecoverySetup
    } else {
        CapabilityPurpose::Setup
    };
    let (ceremony_id, public_key) = state
        .auth
        .start_setup_registration(&token, purpose, Utc::now())
        .await?;
    Ok(Json(json!({
        "ceremony_id": ceremony_id,
        "public_key": public_key,
    })))
}

async fn setup_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CeremonyFinish>,
) -> Result<StatusCode, ApiError> {
    verify_origin_json(&state, &headers)?;
    state
        .auth
        .finish_registration(
            request.ceremony_id,
            CeremonyKind::Registration,
            &request.credential,
            Utc::now(),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RecoveryRequestBody {
    user_id: String,
}

async fn recovery_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RecoveryRequestBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    verify_origin_json(&state, &headers)?;
    let user_id = UserId::new(request.user_id).map_err(|_| ApiError(AuthError::InvalidInput))?;
    let recovery = state.auth.request_recovery(&user_id, Utc::now()).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"request_id": recovery.id, "status": "pending"})),
    ))
}

async fn operator_bootstrap_start(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    verify_origin_json(&state, &headers)?;
    let (ceremony_id, public_key, ceremony_kind) =
        state.auth.start_operator_bootstrap(Utc::now()).await?;
    Ok(Json(json!({
        "ceremony_id": ceremony_id,
        "ceremony_kind": ceremony_kind,
        "public_key": public_key,
    })))
}

async fn operator_bootstrap_finish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CeremonyFinish>,
) -> Result<StatusCode, ApiError> {
    verify_origin_json(&state, &headers)?;
    let kind = request
        .ceremony_kind
        .unwrap_or(CeremonyKind::OperatorBootstrap);
    if !matches!(
        kind,
        CeremonyKind::OperatorBootstrap | CeremonyKind::OperatorRecovery
    ) {
        return Err(ApiError(AuthError::InvalidInput));
    }
    state
        .auth
        .finish_registration(request.ceremony_id, kind, &request.credential, Utc::now())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn pending_recoveries(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    operator(&state, &headers, false).await?;
    let recoveries = state.auth.pending_recoveries().await?;
    Ok(Json(json!({
        "schema_version": 1,
        "recoveries": recoveries,
    })))
}

async fn approve_recovery(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    verify_origin_json(&state, &headers)?;
    let principal = operator(&state, &headers, true).await?;
    state
        .auth
        .approve_recovery(id, &principal.user.id, Utc::now())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RecoverySetupBody {
    user_id: String,
}

async fn issue_recovery_setup(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RecoverySetupBody>,
) -> Result<Json<Value>, ApiError> {
    verify_origin_json(&state, &headers)?;
    let principal = operator(&state, &headers, true).await?;
    let user_id = UserId::new(request.user_id).map_err(|_| ApiError(AuthError::InvalidInput))?;
    let token = state
        .auth
        .issue_recovery_setup(id, &principal.user.id, user_id, Utc::now())
        .await?;
    Ok(Json(json!({
        "setup_fragment": format!("#setup={}", token.expose()),
        "expires_in_seconds": 900,
    })))
}

#[derive(Deserialize)]
struct ApproveUserBody {
    user_id: String,
    email: String,
    display_name: String,
}

async fn approve_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ApproveUserBody>,
) -> Result<Json<Value>, ApiError> {
    verify_origin_json(&state, &headers)?;
    let principal = operator(&state, &headers, true).await?;
    let user_id = UserId::new(request.user_id).map_err(|_| ApiError(AuthError::InvalidInput))?;
    let token = state
        .auth
        .approve_user_and_issue_setup(
            &principal.user.id,
            user_id,
            request.email,
            request.display_name,
            Utc::now(),
        )
        .await?;
    Ok(Json(json!({
        "setup_fragment": format!("#setup={}", token.expose()),
        "expires_in_seconds": 900,
    })))
}

async fn operator_capabilities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CapabilityDocument>, ApiError> {
    operator(&state, &headers, false).await?;
    Ok(Json(CapabilityDocument {
        schema_version: 1,
        audience: "operator",
        capabilities: vec![
            "platform.read",
            "user.approve",
            "recovery.list",
            "recovery.approve",
            "recovery.setup_issue",
        ],
    }))
}

async fn operator(
    state: &AppState,
    headers: &HeaderMap,
    csrf_required: bool,
) -> Result<SessionPrincipal, ApiError> {
    let (token, csrf) = if csrf_required {
        let (token, csrf) = session_and_csrf(headers)?;
        (token, Some(csrf))
    } else {
        (session_token(headers)?, None)
    };
    let principal = state
        .auth
        .authenticate_session(&token, csrf.as_ref(), Utc::now())
        .await?;
    if principal.user.role != Role::Operator {
        return Err(ApiError(AuthError::Forbidden));
    }
    Ok(principal)
}

async fn optional_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<SessionPrincipal>, ApiError> {
    let Some(value) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let token = SecretToken::parse(value)?;
    match state
        .auth
        .authenticate_session(&token, None, Utc::now())
        .await
    {
        Ok(principal) => Ok(Some(principal)),
        Err(AuthError::Unauthenticated) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn verify_origin_json(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError(AuthError::Forbidden))?;
    if origin != state.browser_origin {
        return Err(ApiError(AuthError::Forbidden));
    }
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type != "application/json" {
        return Err(ApiError(AuthError::InvalidInput));
    }
    Ok(())
}

fn session_and_csrf(headers: &HeaderMap) -> Result<(SecretToken, SecretToken), ApiError> {
    let token = session_token(headers)?;
    let csrf = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError(AuthError::Forbidden))
        .and_then(|value| SecretToken::parse(value).map_err(ApiError))?;
    Ok((token, csrf))
}

fn session_token(headers: &HeaderMap) -> Result<SecretToken, ApiError> {
    cookie_value(headers, SESSION_COOKIE)
        .ok_or(ApiError(AuthError::Unauthenticated))
        .and_then(|value| SecretToken::parse(value).map_err(ApiError))
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix(name)?.strip_prefix('='))
}

async fn not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use http::Request;
    use rs_console_auth::AuthConfig;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt as _;

    use super::*;
    use crate::webauthn::WebauthnEngine;

    fn test_state() -> Arc<AppState> {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://console:unused@127.0.0.1:1/console")
            .expect("test URL is valid");
        let store = Arc::new(PgAuthStore::from_pool(pool));
        let engine = Arc::new(
            WebauthnEngine::new("localhost", "http://localhost:4321", false)
                .expect("development WebAuthn config is valid"),
        );
        Arc::new(AppState {
            auth: AuthService::new(Arc::clone(&store), engine, AuthConfig::default()),
            store,
            browser_origin: "http://localhost:4321".to_owned(),
        })
    }

    #[test]
    fn cookie_parser_requires_the_exact_host_cookie_name() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("other=x; __Host-rs_session=right"),
        );
        assert_eq!(cookie_value(&headers, SESSION_COOKIE), Some("right"));
        assert_eq!(cookie_value(&headers, "rs_session"), None);
    }

    #[test]
    fn capability_document_shape_is_versioned() {
        let value = serde_json::to_value(CapabilityDocument {
            schema_version: 1,
            audience: "anonymous",
            capabilities: vec!["auth.login"],
        })
        .expect("serializes");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["audience"], "anonymous");
        assert_eq!(value["capabilities"], json!(["auth.login"]));
    }

    #[tokio::test]
    async fn public_and_private_route_inventories_are_structurally_separate() {
        let public = public_router(test_state());
        let private = private_router(test_state());

        let public_response = public
            .oneshot(
                Request::builder()
                    .uri("/v1/operator/capabilities")
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(public_response.status(), StatusCode::NOT_FOUND);

        let private_response = private
            .oneshot(
                Request::builder()
                    .uri("/v1/auth/login/start")
                    .method(Method::POST)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(private_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn mutating_routes_reject_wrong_origin_before_work() {
        let response = public_router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/v1/auth/login/start")
                    .method(Method::POST)
                    .header(ORIGIN, "https://evil.example")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }
}
