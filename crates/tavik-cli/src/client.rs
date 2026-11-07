use futures_util::{SinkExt, StreamExt};
use std::path::{Path, PathBuf};
use tavik_common::error::{Result, TavikError};
use tavik_common::protocol::{
    Action, ProcessInfo, ProcessStartParams, Request, Response, TavikClientCodec,
};
use tavik_common::system::SystemInfo;
use tokio::net::UnixStream;
use tokio_util::codec::Framed;

pub struct Client {
    socket_path: PathBuf,
}

impl Client {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    #[allow(dead_code)]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn connect(&self) -> Result<Framed<UnixStream, TavikClientCodec>> {
        let stream = UnixStream::connect(&self.socket_path).await.map_err(|e| {
            TavikError::DaemonUnreachable(format!(
                "Cannot connect to Tavik daemon at {:?}: {}. Is 'tavikd' running?",
                self.socket_path, e
            ))
        })?;
        Ok(Framed::new(stream, TavikClientCodec::default()))
    }

    pub async fn send_action(&self, action: Action) -> Result<serde_json::Value> {
        let mut framed = self.connect().await?;
        let req = Request::new(action);
        let req_id = req.id.clone();

        framed.send(req).await?;

        if let Some(resp_res) = framed.next().await {
            let resp: Response = resp_res?;
            if resp.id != req_id {
                return Err(TavikError::Protocol(format!(
                    "Mismatched response ID: expected {}, got {}",
                    req_id, resp.id
                )));
            }
            resp.result
        } else {
            Err(TavikError::Protocol(
                "Daemon closed connection without responding".to_string(),
            ))
        }
    }

    pub async fn ping(&self) -> Result<String> {
        let val = self.send_action(Action::Ping).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn version(&self) -> Result<serde_json::Value> {
        self.send_action(Action::Version).await
    }

    pub async fn info(&self) -> Result<SystemInfo> {
        let val = self.send_action(Action::Info).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn process_start(&self, params: ProcessStartParams) -> Result<ProcessInfo> {
        let val = self.send_action(Action::ProcessStart(params)).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn process_stop(&self, id: String, signal: Option<i32>) -> Result<ProcessInfo> {
        let val = self.send_action(Action::ProcessStop { id, signal }).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn process_list(&self) -> Result<Vec<ProcessInfo>> {
        let val = self.send_action(Action::ProcessList).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn process_inspect(&self, id: String) -> Result<ProcessInfo> {
        let val = self.send_action(Action::ProcessInspect { id }).await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn container_create(&self, id: String, bundle: String) -> Result<serde_json::Value> {
        self.send_action(Action::ContainerCreate { id, bundle })
            .await
    }

    pub async fn container_start(&self, id: String) -> Result<serde_json::Value> {
        self.send_action(Action::ContainerStart { id }).await
    }

    pub async fn container_state(&self, id: String) -> Result<serde_json::Value> {
        self.send_action(Action::ContainerState { id }).await
    }

    pub async fn container_kill(&self, id: String, signal: String) -> Result<String> {
        let val = self
            .send_action(Action::ContainerKill { id, signal })
            .await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn container_delete(&self, id: String, force: bool) -> Result<String> {
        let val = self
            .send_action(Action::ContainerDelete { id, force })
            .await?;
        serde_json::from_value(val).map_err(Into::into)
    }

    pub async fn shutdown(&self) -> Result<String> {
        let val = self.send_action(Action::Shutdown).await?;
        serde_json::from_value(val).map_err(Into::into)
    }
}
