use clap::Parser;
use std::path::PathBuf;
use tavik_common::constants::{default_socket_path, default_state_dir};
use tavik_daemon::DaemonServer;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "tavikd",
    about = "TAVIK Container Engine Daemon",
    version = tavik_common::constants::ENGINE_VERSION
)]
struct Args {
    /// Path to Unix domain socket for IPC
    #[arg(short, long, env = "TAVIK_SOCKET")]
    socket: Option<PathBuf>,

    /// Path to persistent state directory
    #[arg(long, env = "TAVIK_STATE_DIR")]
    state_dir: Option<PathBuf>,

    /// Run daemon in foreground (default)
    #[arg(short, long, default_value_t = true)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tavik=debug,tavik_daemon=debug,tavik_core=debug,info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let socket_path = args.socket.unwrap_or_else(default_socket_path);
    let state_dir = args.state_dir.unwrap_or_else(default_state_dir);

    info!(
        "Starting TAVIK daemon v{} on socket {:?}",
        tavik_common::constants::ENGINE_VERSION,
        socket_path
    );

    let server = DaemonServer::new(socket_path, state_dir)?;

    tokio::select! {
        res = server.run() => {
            if let Err(e) = res {
                error!("Daemon terminated with error: {}", e);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT; initiating graceful shutdown");
        }
    }

    Ok(())
}
