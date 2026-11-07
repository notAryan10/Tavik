use futures_util::{SinkExt, StreamExt};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tavik_common::constants::ENGINE_VERSION;
use tavik_common::error::{Result, TavikError};
use tavik_common::protocol::{Action, Request, Response, TavikClientCodec, TavikServerCodec};
use tavik_common::system::SystemInfo;
use tavik_core::{ProcessSupervisor, StateStore};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

pub struct DaemonServer {
    socket_path: PathBuf,
    state_dir: PathBuf,
    supervisor: Arc<ProcessSupervisor>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DaemonServer {
    pub fn new(socket_path: PathBuf, state_dir: PathBuf) -> Result<Self> {
        let store = StateStore::new(state_dir.clone())?;
        let supervisor = Arc::new(ProcessSupervisor::new(store));
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            socket_path,
            state_dir,
            supervisor,
            shutdown_tx,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub async fn run(&self) -> Result<()> {
        // Ensure parent directory for socket exists
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Clean up stale socket file if it exists
        if self.socket_path.exists() {
            // Check if another daemon is already responding
            if let Ok(mut stream) = UnixStream::connect(&self.socket_path).await {
                let mut framed = Framed::new(&mut stream, TavikClientCodec::default());
                let ping_req = Request::new(Action::Ping);
                if framed.send(ping_req).await.is_ok() {
                    return Err(TavikError::AlreadyExists(format!(
                        "A Tavik daemon is already running and responding at {:?}",
                        self.socket_path
                    )));
                }
            }
            warn!("Removing stale socket file at {:?}", self.socket_path);
            let _ = fs::remove_file(&self.socket_path);
        }

        let listener = UnixListener::bind(&self.socket_path).map_err(|e| {
            TavikError::Io(format!(
                "Failed to bind Unix socket at {:?}: {}",
                self.socket_path, e
            ))
        })?;

        // Set safe socket permissions (0600: read/write by owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::Permissions::from_mode(0o600);
            if let Err(e) = fs::set_permissions(&self.socket_path, permissions) {
                warn!("Failed to restrict socket permissions: {}", e);
            }
        }

        info!(
            "Tavik daemon listening on Unix domain socket: {:?}",
            self.socket_path
        );

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, _)) => {
                            let supervisor = self.supervisor.clone();
                            let shutdown_tx = self.shutdown_tx.clone();
                            let state_dir = self.state_dir.clone();
                            let socket_path = self.socket_path.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    supervisor,
                                    shutdown_tx,
                                    &state_dir,
                                    &socket_path
                                ).await {
                                    debug!("Connection closed with error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept incoming socket connection: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Daemon received shutdown signal; terminating listener loop");
                    break;
                }
            }
        }

        // Clean up socket file on clean exit
        if self.socket_path.exists() {
            let _ = fs::remove_file(&self.socket_path);
        }

        info!("Tavik daemon stopped successfully");
        Ok(())
    }
}

async fn handle_connection(
    stream: UnixStream,
    supervisor: Arc<ProcessSupervisor>,
    shutdown_tx: broadcast::Sender<()>,
    state_dir: &Path,
    socket_path: &Path,
) -> Result<()> {
    let mut framed = Framed::new(stream, TavikServerCodec::default());

    while let Some(req_res) = framed.next().await {
        let req: Request = req_res?;
        let req_id = req.id.clone();

        let resp = match req.action {
            Action::Ping => Response::ok(req_id, &"pong")?,
            Action::Version => {
                let version_info = serde_json::json!({
                    "engine": tavik_common::constants::ENGINE_NAME,
                    "version": ENGINE_VERSION,
                });
                Response::ok(req_id, &version_info)?
            }
            Action::Info => {
                let info = SystemInfo::detect(state_dir, socket_path);
                Response::ok(req_id, &info)?
            }
            Action::ProcessStart(params) => match supervisor.spawn(params).await {
                Ok(proc_info) => Response::ok(req_id, &proc_info)?,
                Err(err) => Response::err(req_id, err),
            },
            Action::ProcessStop { id, signal } => match supervisor.stop(&id, signal).await {
                Ok(proc_info) => Response::ok(req_id, &proc_info)?,
                Err(err) => Response::err(req_id, err),
            },
            Action::ProcessList => {
                let list = supervisor.list().await;
                Response::ok(req_id, &list)?
            }
            Action::ProcessInspect { id } => match supervisor.inspect(&id).await {
                Ok(proc_info) => Response::ok(req_id, &proc_info)?,
                Err(err) => Response::err(req_id, err),
            },
            Action::Shutdown => {
                info!("Shutdown request received via RPC");
                let _ = shutdown_tx.send(());
                Response::ok(req_id, &"shutting down")?
            }
        };

        framed.send(resp).await?;
    }

    Ok(())
}
