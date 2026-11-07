use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tavik_common::constants::default_state_dir;
use tavik_runtime::{ContainerExecutor, Spec};

#[derive(Parser, Debug)]
#[command(
    name = "tavikr",
    about = "TAVIK OCI Container Runtime",
    version = tavik_common::constants::ENGINE_VERSION
)]
struct Cli {
    /// Root directory for container runtime state
    #[arg(long, env = "TAVIK_ROOT")]
    root: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create an OCI container from a bundle
    Create {
        /// Container identifier
        container_id: String,

        /// Path to the OCI container bundle directory
        #[arg(short, long)]
        bundle: PathBuf,
    },

    /// Start an previously created container
    Start {
        /// Container identifier
        container_id: String,
    },

    /// Query the current OCI state of a container
    State {
        /// Container identifier
        container_id: String,
    },

    /// Send a signal to a container's init process
    Kill {
        /// Container identifier
        container_id: String,

        /// Signal number or name (e.g. 15 or SIGTERM)
        signal: String,
    },

    /// Delete a container and release runtime resources
    Delete {
        /// Container identifier
        container_id: String,

        /// Force deletion even if running
        #[arg(short, long)]
        force: bool,
    },

    /// Output a standard default OCI spec (config.json)
    Spec,

    /// Internal container init entrypoint
    #[command(name = "init")]
    Init {
        /// Container identifier
        id: String,

        /// State directory
        #[arg(long)]
        state_dir: PathBuf,
    },
}

fn parse_signal(sig: &str) -> i32 {
    match sig.to_uppercase().as_str() {
        "SIGTERM" | "15" => 15,
        "SIGKILL" | "9" => 9,
        "SIGINT" | "2" => 2,
        "SIGHUP" | "1" => 1,
        "SIGQUIT" | "3" => 3,
        "SIGSTOP" | "19" => 19,
        "SIGCONT" | "18" => 18,
        other => other.parse::<i32>().unwrap_or(15),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let state_dir = cli
        .root
        .unwrap_or_else(|| default_state_dir().join("runtime"));

    let executor = ContainerExecutor::new(state_dir)?;

    match cli.command {
        Commands::Create {
            container_id,
            bundle,
        } => {
            let state = executor.create(&container_id, &bundle)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::Start { container_id } => {
            let state = executor.start(&container_id)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::State { container_id } => {
            let state = executor.load_state(&container_id)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::Kill {
            container_id,
            signal,
        } => {
            let sig_num = parse_signal(&signal);
            executor.kill(&container_id, sig_num)?;
            println!("Signal {} sent to container {}", signal, container_id);
        }
        Commands::Delete {
            container_id,
            force,
        } => {
            executor.delete(&container_id, force)?;
            println!("Container {} deleted", container_id);
        }
        Commands::Spec => {
            let spec = Spec::default_linux();
            println!("{}", serde_json::to_string_pretty(&spec)?);
        }
        Commands::Init { id, state_dir } => {
            if let Err(e) = tavik_runtime::init::run_init_trampoline(&state_dir, &id) {
                eprintln!("tavikr init error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
