use crate::constants::DEFAULT_MAX_FRAME_BYTES;
use crate::error::{Result, TavikError};
use bytes::{Buf, BufMut, BytesMut};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub action: Action,
}

impl Request {
    pub fn new(action: Action) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            action,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    Ping,
    Version,
    Info,
    ProcessStart(ProcessStartParams),
    ProcessStop { id: String, signal: Option<i32> },
    ProcessList,
    ProcessInspect { id: String },
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessStartParams {
    pub command: String,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessStatus {
    Created,
    Running,
    Stopped,
    Exited { code: i32 },
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub id: String,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub pid: Option<u32>,
    pub status: ProcessStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub result: std::result::Result<serde_json::Value, TavikError>,
}

impl Response {
    pub fn ok<T: Serialize>(id: String, payload: &T) -> std::result::Result<Self, TavikError> {
        let value = serde_json::to_value(payload)?;
        Ok(Self {
            id,
            result: Ok(value),
        })
    }

    pub fn err(id: String, err: TavikError) -> Self {
        Self {
            id,
            result: Err(err),
        }
    }
}

/// Length-delimited framing codec for Unix domain socket streams.
/// Wire format: [4 bytes Big-Endian payload length][JSON Payload]
#[derive(Debug, Clone)]
pub struct TavikCodec<In, Out> {
    max_frame_bytes: usize,
    _phantom: std::marker::PhantomData<fn(Out) -> In>,
}

pub type TavikServerCodec = TavikCodec<Request, Response>;
pub type TavikClientCodec = TavikCodec<Response, Request>;

impl<In, Out> Default for TavikCodec<In, Out> {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<In, Out> TavikCodec<In, Out> {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self {
            max_frame_bytes,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<In: for<'de> Deserialize<'de>, Out> Decoder for TavikCodec<In, Out> {
    type Item = In;
    type Error = TavikError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > self.max_frame_bytes {
            return Err(TavikError::Protocol(format!(
                "Incoming frame size {} exceeds maximum allowed {}",
                length, self.max_frame_bytes
            )));
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        src.advance(4);
        let payload = src.split_to(length);
        let item: In = serde_json::from_slice(&payload)?;
        Ok(Some(item))
    }
}

impl<In, Out: Serialize> Encoder<Out> for TavikCodec<In, Out> {
    type Error = TavikError;

    fn encode(&mut self, item: Out, dst: &mut BytesMut) -> Result<()> {
        let payload = serde_json::to_vec(&item)?;
        if payload.len() > self.max_frame_bytes {
            return Err(TavikError::Protocol(format!(
                "Outgoing frame size {} exceeds maximum allowed {}",
                payload.len(),
                self.max_frame_bytes
            )));
        }

        dst.reserve(4 + payload.len());
        dst.put_u32(payload.len() as u32);
        dst.put_slice(&payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_roundtrip() {
        let mut codec = TavikCodec::<Request, Request>::default();
        let mut buf = BytesMut::new();

        let req = Request::new(Action::Ping);
        codec.encode(req.clone(), &mut buf).unwrap();

        let decoded: Option<Request> = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
        let decoded = decoded.unwrap();
        assert_eq!(decoded.id, req.id);
        match decoded.action {
            Action::Ping => {}
            _ => panic!("Expected Ping action"),
        }
    }
}
