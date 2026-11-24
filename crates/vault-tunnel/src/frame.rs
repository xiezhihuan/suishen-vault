//! 握手阶段的定长前缀 JSON 帧。
use crate::{Result, TunnelError};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX: usize = 4096;

pub async fn send<T: Serialize>(io: &mut (impl AsyncWrite + Unpin), value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).map_err(|_| TunnelError)?;
    if body.len() > MAX {
        return Err(TunnelError);
    }
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    io.write_all(&out).await?;
    io.flush().await?;
    Ok(())
}

pub async fn recv<T: DeserializeOwned>(io: &mut (impl AsyncRead + Unpin)) -> Result<T> {
    let len = io.read_u32().await? as usize;
    if len > MAX {
        return Err(TunnelError);
    }
    let mut body = vec![0; len];
    io.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(|_| TunnelError)
}
