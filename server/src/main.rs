#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration, Utc};
use clap::{Parser, Subcommand};
use rs_console_auth::{AuthConfig, AuthStore, Capability, CapabilityPurpose, SecretToken};
use rs_console_policy::UserId;
use rs_console_server::http::{private_router, public_router, AppState};
use rs_console_server::repository::PgAuthStore;
use rs_console_server::webauthn::WebauthnEngine;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "rs-console")]
#[command(about = "RS Platform console API and recovery utility")]
struct Cli {
    #[arg(
        long,
        env = "RS_DATABASE_URL_FILE",
        default_value = "/run/secrets/database-url"
    )]
    database_url_file: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve(ServeArgs),
    BreakGlass(BreakGlassArgs),
    SeedOperator(SeedOperatorArgs),
    RotateAuthEpoch(RotateAuthEpochArgs),
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "RS_PUBLIC_LISTEN", default_value = "0.0.0.0:8080")]
    public_listen: SocketAddr,

    #[arg(long, env = "RS_PRIVATE_LISTEN", default_value = "0.0.0.0:8081")]
    private_listen: SocketAddr,

    #[arg(long, env = "RS_RP_ID", default_value = "ricardosaad.com")]
    rp_id: String,

    #[arg(
        long,
        env = "RS_BROWSER_ORIGIN",
        default_value = "https://ricardosaad.com"
    )]
    browser_origin: String,

    #[arg(long, env = "RS_ENVIRONMENT", default_value = "production")]
    environment: String,

    #[arg(long, env = "RS_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    database_max_connections: u32,
}

#[derive(clap::Args)]
struct BreakGlassArgs {
    #[arg(long, env = "RS_BREAK_GLASS_ENABLED", default_value_t = false)]
    enabled: bool,

    #[arg(long)]
    operator_user_id: String,

    #[arg(long)]
    revoke_credential: Uuid,

    #[arg(long)]
    reason: String,

    #[arg(long, default_value_t = 10)]
    window_minutes: i64,

    #[arg(long)]
    confirm: String,
}

#[derive(clap::Args)]
struct SeedOperatorArgs {
    #[arg(long, env = "RS_SEED_OPERATOR_ENABLED", default_value_t = false)]
    enabled: bool,

    #[arg(long)]
    operator_user_id: String,

    #[arg(long)]
    email: String,

    #[arg(long)]
    display_name: String,

    #[arg(long)]
    confirm: String,
}

#[derive(clap::Args)]
struct RotateAuthEpochArgs {
    #[arg(long, env = "RS_ROTATE_AUTH_EPOCH_ENABLED", default_value_t = false)]
    enabled: bool,

    #[arg(long)]
    reason: String,

    #[arg(long)]
    confirm: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let database_url = std::fs::read_to_string(&cli.database_url_file)
        .map_err(|error| format!("failed to read database URL file: {error}"))?;
    let database_url = database_url.trim();
    if database_url.is_empty() {
        return Err("database URL file is empty".into());
    }

    match cli.command {
        Command::Serve(args) => serve(database_url, args).await,
        Command::BreakGlass(args) => break_glass(database_url, args).await,
        Command::SeedOperator(args) => seed_operator(database_url, args).await,
        Command::RotateAuthEpoch(args) => rotate_auth_epoch(database_url, args).await,
    }
}

async fn serve(database_url: &str, args: ServeArgs) -> Result<(), Box<dyn std::error::Error>> {
    let production = match args.environment.as_str() {
        "production" => true,
        "development" => false,
        _ => return Err("RS_ENVIRONMENT must be production or development".into()),
    };
    if args.public_listen == args.private_listen {
        return Err("public and private listeners must be distinct".into());
    }
    let store = Arc::new(PgAuthStore::connect(database_url, args.database_max_connections).await?);
    store.migrate().await?;
    let engine = Arc::new(WebauthnEngine::new(
        &args.rp_id,
        &args.browser_origin,
        production,
    )?);
    let auth = rs_console_auth::AuthService::new(Arc::clone(&store), engine, AuthConfig::default());
    let state = Arc::new(AppState {
        auth,
        store,
        browser_origin: args.browser_origin,
    });

    let public_listener = TcpListener::bind(args.public_listen).await?;
    let private_listener = TcpListener::bind(args.private_listen).await?;
    info!(address = %args.public_listen, "public listener started");
    info!(address = %args.private_listen, "private listener started");

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let public_shutdown = shutdown_rx(shutdown_tx.subscribe());
    let private_shutdown = shutdown_rx(shutdown_tx.subscribe());
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });

    let public = axum::serve(public_listener, public_router(Arc::clone(&state)))
        .with_graceful_shutdown(public_shutdown);
    let private = axum::serve(private_listener, private_router(state))
        .with_graceful_shutdown(private_shutdown);
    tokio::try_join!(public, private)?;
    Ok(())
}

async fn break_glass(
    database_url: &str,
    args: BreakGlassArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    const CONFIRMATION: &str = "INVALIDATE OPERATOR AUTH";
    if !args.enabled || args.confirm != CONFIRMATION {
        return Err(
            "break-glass requires RS_BREAK_GLASS_ENABLED=true and exact confirmation".into(),
        );
    }
    if args.reason.trim().len() < 12 {
        return Err("break-glass reason must contain at least 12 characters".into());
    }
    if !(1..=15).contains(&args.window_minutes) {
        return Err("registration window must be between 1 and 15 minutes".into());
    }
    let operator_user_id =
        UserId::new(args.operator_user_id).map_err(|_| "invalid operator user ID")?;
    let store = PgAuthStore::connect(database_url, 2).await?;
    let now = Utc::now();
    let token = SecretToken::generate();
    store
        .break_glass(
            args.revoke_credential,
            Capability {
                id: Uuid::new_v4(),
                user_id: operator_user_id,
                purpose: CapabilityPurpose::OperatorRecovery,
                token_hash: token.hash(),
                expires_at: now + Duration::minutes(args.window_minutes),
            },
            now,
            args.reason.trim(),
        )
        .await?;
    warn!(
        credential_id = %args.revoke_credential,
        window_minutes = args.window_minutes,
        "operator sessions and ceremonies invalidated; bounded private registration window opened"
    );
    Ok(())
}

async fn seed_operator(
    database_url: &str,
    args: SeedOperatorArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    const CONFIRMATION: &str = "SEED FIRST OPERATOR";
    if !args.enabled || args.confirm != CONFIRMATION {
        return Err(
            "seed-operator requires RS_SEED_OPERATOR_ENABLED=true and exact confirmation".into(),
        );
    }
    let operator_user_id =
        UserId::new(args.operator_user_id).map_err(|_| "invalid operator user ID")?;
    let store = Arc::new(PgAuthStore::connect(database_url, 2).await?);
    store.migrate().await?;
    let engine = Arc::new(WebauthnEngine::new(
        "ricardosaad.com",
        "https://ricardosaad.com",
        true,
    )?);
    let auth = rs_console_auth::AuthService::new(store, engine, AuthConfig::default());
    auth.seed_operator(
        operator_user_id.clone(),
        args.email,
        args.display_name,
        Utc::now(),
    )
    .await?;
    warn!(
        operator_user_id = %operator_user_id,
        "first operator row created; register the passkey through the private bootstrap endpoint"
    );
    Ok(())
}

async fn rotate_auth_epoch(
    database_url: &str,
    args: RotateAuthEpochArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    const CONFIRMATION: &str = "ROTATE ALL AUTH EPOCHS";
    if !args.enabled || args.confirm != CONFIRMATION {
        return Err(
            "rotate-auth-epoch requires RS_ROTATE_AUTH_EPOCH_ENABLED=true and exact confirmation"
                .into(),
        );
    }
    let store = Arc::new(PgAuthStore::connect(database_url, 2).await?);
    let engine = Arc::new(WebauthnEngine::new(
        "ricardosaad.com",
        "https://ricardosaad.com",
        true,
    )?);
    let auth = rs_console_auth::AuthService::new(store, engine, AuthConfig::default());
    let users = auth
        .rotate_all_auth_epochs(Utc::now(), &args.reason)
        .await?;
    warn!(
        users,
        "authentication epochs advanced; restored sessions, ceremonies, and setup capabilities are invalid"
    );
    Ok(())
}

async fn shutdown_rx(mut receiver: broadcast::Receiver<()>) {
    let _ = receiver.recv().await;
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        if tokio::signal::ctrl_c().await.is_err() {
            warn!("failed to install ctrl-c handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
