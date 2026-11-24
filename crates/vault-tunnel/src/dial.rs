//! 出站连接：TCP → 外层 TLS → HTTP/1.1 升级。不使用系统代理，不跟随重定向。
use crate::{Endpoint, HANDSHAKE_TIMEOUT, Result, TunnelError, tls};
use http_body_util::Empty;
use hyper::{Request, StatusCode, body::Bytes, header, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type Connection = TokioIo<Upgraded>;

/// 到跳板的连接，除回环 HTTP 外都有外层 TLS。
pub async fn connect(endpoint: &Endpoint, ca: Option<&str>) -> Result<Box<dyn Io>> {
    let tcp = TcpStream::connect((endpoint.host(), endpoint.port())).await?;
    tcp.set_nodelay(true)?;
    Ok(if endpoint.tls() {
        Box::new(tls::https(tcp, endpoint, ca).await?)
    } else {
        Box::new(tcp)
    })
}

/// 建立升级连接。`None` 表示跳板正常答复但不接受升级（离线）。
pub async fn upgrade(
    endpoint: &Endpoint,
    ca: Option<&str>,
    path: &str,
    protocol: &'static str,
) -> Result<Option<Connection>> {
    let work = async {
        let io = connect(endpoint, ca).await?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .map_err(|_| TunnelError)?;
        // 升级后由它交出底层连接
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let req = Request::get(path)
            .header(header::HOST, endpoint.authority())
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, protocol)
            .body(Empty::<Bytes>::new())
            .map_err(|_| TunnelError)?;
        let reply = send.send_request(req).await.map_err(|_| TunnelError)?;
        if reply.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Ok(None);
        }
        let up = hyper::upgrade::on(reply).await.map_err(|_| TunnelError)?;
        Ok(Some(TokioIo::new(up)))
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, work)
        .await
        .map_err(|_| TunnelError)?
}
