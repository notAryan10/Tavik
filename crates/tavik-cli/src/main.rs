mod client;

use clap::{Parser, Subcommand};
use client::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use tavik_common::constants::{
    default_socket_path, default_state_dir, ENGINE_NAME, ENGINE_VERSION,
};
use tavik_common::protocol::ProcessStartParams;

#[derive(Parser, Debug)]
#[command(
    name = "tavik",
    about = "TAVIK — Containers. Without the overhead.",
    version = ENGINE_VERSION
)]
struct Cli {
    /// Override daemon Unix domain socket path
    #[arg(short, long, global = true, env = "TAVIK_SOCKET")]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Display TAVIK engine and CLI version information
    Version,

    /// Ping the running TAVIK daemon
    Ping,

    /// Request graceful shutdown of the running daemon
    Shutdown,

    /// Display system information, kernel features, and daemon status
    Info,

    /// Run the TAVIK daemon server directly
    Daemon {
        #[arg(long, env = "TAVIK_STATE_DIR")]
        state_dir: Option<PathBuf>,

        #[arg(short, long, default_value_t = true)]
        foreground: bool,
    },

    /// List supervised workloads
    Ps,

    /// Inspect a workload by ID
    Inspect {
        /// Workload identifier
        id: String,
    },

    /// Stop a running workload
    Stop {
        /// Workload identifier
        id: String,

        /// Custom termination signal number (e.g. 15 for SIGTERM, 9 for SIGKILL)
        #[arg(short, long)]
        signal: Option<i32>,
    },

    /// Run and supervise a task process (foundation process supervision)
    RunTask {
        /// Optional workload name
        #[arg(short, long)]
        name: Option<String>,

        /// Working directory
        #[arg(short, long)]
        workdir: Option<String>,

        /// Environment variables (KEY=VALUE)
        #[arg(short, long, value_parser = parse_key_val)]
        env: Vec<(String, String)>,

        /// Command to execute
        command: String,

        /// Arguments for the command
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("Invalid KEY=VALUE pair: '{}'", s))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let socket_path = cli.socket.unwrap_or_else(default_socket_path);

    match cli.command {
        Commands::Ping => {
            let client = Client::new(socket_path);
            match client.ping().await {
                Ok(resp) => println!("{}", resp),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Shutdown => {
            let client = Client::new(socket_path);
            match client.shutdown().await {
                Ok(resp) => println!("{}", resp),
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Version => {
            println!("{} CLI Version: {}", ENGINE_NAME, ENGINE_VERSION);
            let client = Client::new(socket_path.clone());
            match client.version().await {
                Ok(v) => {
                    if let Some(daemon_ver) = v.get("version").and_then(|s| s.as_str()) {
                        println!("Daemon Version: {}", daemon_ver);
                    } else {
                        println!("Daemon Response: {}", v);
                    }
                }
                Err(e) => {
                    println!("Daemon: not reachable ({})", e);
                }
            }
        }
        Commands::Info => {
            let client = Client::new(socket_path.clone());
            match client.info().await {
                Ok(info) => {
                    println!("=== {} Engine Info ===", info.engine_name);
                    println!("Engine Version:       {}", info.engine_version);
                    println!("Operating System:     {}", info.os);
                    println!("Kernel:               {}", info.kernel);
                    println!("Architecture:         {}", info.arch);
                    println!("Root Privileges:      {}", info.is_root);
                    println!("cgroups v2 Support:   {}", info.cgroups_v2_available);
                    println!("Namespaces Support:   {}", info.namespaces_available);
                    println!("OverlayFS Support:    {}", info.overlayfs_available);
                    println!("Isolation Ready:      {}", info.isolation_ready);
                    println!("State Directory:      {}", info.state_dir);
                    println!("Socket Path:          {}", info.socket_path);

                    if !info.isolation_ready {
                        println!("\n[Notice] Host platform does not provide full Linux isolation features (cgroups v2, namespaces, or overlayfs).");
                        println!("         Foundation process supervision is active. Container isolation (Phase 2+) requires a Linux kernel.");
                    }
                }
                Err(e) => {
                    eprintln!(
                        "Error connecting to Tavik daemon at {:?}: {}",
                        socket_path, e
                    );
                    std::process::exit(1);
                }
            }
        }
        Commands::Daemon {
            state_dir,
            foreground: _,
        } => {
            let state = state_dir.unwrap_or_else(default_state_dir);
            let server = tavik_daemon::DaemonServer::new(socket_path.clone(), state)?;
            println!(
                "Starting TAVIK daemon v{} on socket {:?}",
                ENGINE_VERSION, socket_path
            );
            server.run().await?;
        }
        Commands::Ps => {
            let client = Client::new(socket_path);
            let list = client.process_list().await?;

            if list.is_empty() {
                println!("No supervised workloads found.");
                return Ok(());
            }

            println!(
                "{:<14} {:<20} {:<15} {:<10} {:<25} COMMAND",
                "ID", "NAME", "STATUS", "PID", "CREATED"
            );
            println!("{}", "-".repeat(95));

            for p in list {
                let status_str = match &p.status {
                    tavik_common::protocol::ProcessStatus::Created => "Created".to_string(),
                    tavik_common::protocol::ProcessStatus::Running => "Running".to_string(),
                    tavik_common::protocol::ProcessStatus::Stopped => "Stopped".to_string(),
                    tavik_common::protocol::ProcessStatus::Exited { code } => {
                        format!("Exited ({})", code)
                    }
                    tavik_common::protocol::ProcessStatus::Failed { error } => {
                        format!("Failed ({})", error)
                    }
                };

                let pid_str = p
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let created_str = p.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
                let full_cmd = format!("{} {}", p.command, p.args.join(" "));

                println!(
                    "{:<14} {:<20} {:<15} {:<10} {:<25} {}",
                    p.id, p.name, status_str, pid_str, created_str, full_cmd
                );
            }
        }
        Commands::Inspect { id } => {
            let client = Client::new(socket_path);
            let info = client.process_inspect(id).await?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::Stop { id, signal } => {
            let client = Client::new(socket_path);
            let info = client.process_stop(id, signal).await?;
            println!("Workload {} stopped (status: {:?})", info.id, info.status);
        }
        Commands::RunTask {
            name,
            workdir,
            env,
            command,
            args,
        } => {
            let client = Client::new(socket_path);
            let mut env_map = HashMap::new();
            for (k, v) in env {
                env_map.insert(k, v);
            }

            let params = ProcessStartParams {
                command,
                args,
                env: env_map,
                working_dir: workdir,
                name,
            };

            let info = client.process_start(params).await?;
            println!(
                "Supervised workload started: {} (ID: {}, PID: {:?})",
                info.name, info.id, info.pid
            );
        }
    }

    Ok(())
}
