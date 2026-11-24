//! 公网跳板。部署在用户自己的服务器上，前面由 Caddy 或 Nginx 提供 HTTPS。
//!
//! 只搬运字节：不落盘、不记录正文、不记录来源地址。日志只有固定的事件名。
mod limit;
mod state;

pub use state::{CODE_TTL, State};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, combinators::BoxBody};
use hyper::{
    HeaderMap, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn, upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use limit::Limiter;
use std::{
    convert::Infallible,
    io::Write,
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    time::timeout,
};
use vault_tunnel::{
    BRIDGE_PATH, BRIDGE_PROTOCOL, DEVICE_PATH, DEVICE_PROTOCOL, PING, PING_INTERVAL, PING_TIMEOUT,
    PublicKey, STREAM_BRIDGE, STREAM_CONTROL, STREAM_DIRECT, SUPERSEDED, frame,
    handshake::{self, Verdict},
    mux::{self, Opener, Stream},
};

const MAX_BODY: usize = 64 * 1024;
const MAX_CONNECTIONS: usize = 256;
/// 同时进行的转发。
const MAX_FORWARDS: usize = 64;
/// 同时进行、尚未证明身份的设备握手。
const MAX_HANDSHAKES: usize = 8;
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(60);
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(120);

type Body = BoxBody<Bytes, hyper::Error>;
type Reply = Response<Body>;

#[derive(Clone)]
pub struct Config {
    /// 对外的主机名，即客户端看到的 `Host`，非 443 端口要带端口。
    pub host: String,
    pub state: State,
    /// 每来源每分钟请求数。
    pub per_source: u32,
    /// 全局每分钟请求数。
    pub total: u32,
}

impl Config {
    pub fn new(host: impl Into<String>, state: State) -> Self {
        Self {
            host: host.into(),
            state,
            per_source: 60,
            total: 300,
        }
    }
}

struct Online {
    id: u64,
    key: PublicKey,
    direct: bool,
    opener: Opener,
    /// 发送 `true` 表示已被取代。
    kick: oneshot::Sender<bool>,
}

struct Relay {
    config: Config,
    limiter: Limiter,
    online: Mutex<Option<Online>>,
    next: AtomicU64,
    forwards: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}

/// 事件名是固定文本，不含任何来访内容。
fn log(event: &'static str) {
    let _ = writeln!(std::io::stderr(), "vault-relay {event}");
}

fn text(status: StatusCode, error: &'static str) -> Reply {
    let body = Full::new(Bytes::from(format!("{{\"error\":\"{error}\"}}")));
    let mut r = Response::new(body.map_err(|e| match e {}).boxed());
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    r
}

/// 没有设备、设备离线、公网已关闭、不允许直连、路径不存在、主机名不符，对外都是这一个答复。
fn offline() -> Reply {
    text(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}

fn busy() -> Reply {
    text(StatusCode::TOO_MANY_REQUESTS, "rate_limited")
}

fn single<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut all = h.get_all(name).iter();
    let first = all.next()?;
    all.next().is_none().then(|| first.to_str().ok()).flatten()
}

/// 反向代理追加在最后的那个地址。跳板只监听代理能到达的地址，所以可信。
fn source(h: &HeaderMap) -> &str {
    h.get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .map_or("", str::trim)
}

/// 逐跳头与代理追加的来源信息不转给设备。
fn strip(h: &mut HeaderMap) {
    let listed: Vec<String> = h
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let drop: Vec<_> = h
        .keys()
        .filter(|k| {
            let k = k.as_str();
            listed.iter().any(|l| l == k)
                || k.starts_with("proxy-")
                || k.starts_with("x-forwarded-")
                || matches!(
                    k,
                    "connection"
                        | "keep-alive"
                        | "te"
                        | "trailer"
                        | "transfer-encoding"
                        | "upgrade"
                        | "forwarded"
                        | "via"
                        | "x-real-ip"
                )
        })
        .cloned()
        .collect();
    for k in drop {
        h.remove(k);
    }
}

fn wants(h: &HeaderMap, protocol: &str) -> bool {
    single(h, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case(protocol))
}

fn switching(protocol: &'static str) -> Reply {
    let mut r = text(StatusCode::SWITCHING_PROTOCOLS, "");
    *r.body_mut() = Full::new(Bytes::new()).map_err(|e| match e {}).boxed();
    let h = r.headers_mut();
    h.clear();
    h.insert(
        header::CONNECTION,
        header::HeaderValue::from_static("Upgrade"),
    );
    h.insert(header::UPGRADE, header::HeaderValue::from_static(protocol));
    r
}

impl Relay {
    fn online(&self) -> MutexGuard<'_, Option<Online>> {
        self.online.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn handle(self: Arc<Self>, mut req: Request<Incoming>) -> Reply {
        if !self.limiter.allow(source(req.headers())) {
            return busy();
        }
        if single(req.headers(), "host") != Some(&self.config.host) {
            return offline();
        }
        match req.uri().path() {
            DEVICE_PATH if wants(req.headers(), DEVICE_PROTOCOL) => {
                let Ok(permit) = self.handshakes.clone().try_acquire_owned() else {
                    return busy();
                };
                tokio::spawn(self.device(hyper::upgrade::on(&mut req), permit));
                switching(DEVICE_PROTOCOL)
            }
            BRIDGE_PATH if wants(req.headers(), BRIDGE_PROTOCOL) => {
                let Ok(permit) = self.forwards.clone().try_acquire_owned() else {
                    return busy();
                };
                let Some(stream) = self.open(STREAM_BRIDGE).await else {
                    return offline();
                };
                tokio::spawn(splice(hyper::upgrade::on(&mut req), stream, permit));
                switching(BRIDGE_PROTOCOL)
            }
            p if p.starts_with("/_relay") => offline(),
            _ => self.direct(req).await,
        }
    }

    /// 向设备开一条流。设备不在线或不允许这种访问方式时为 `None`。
    async fn open(&self, kind: u8) -> Option<Stream> {
        let opener = self
            .online()
            .as_ref()
            .filter(|o| kind != STREAM_DIRECT || o.direct)
            .map(|o| o.opener.clone())?;
        timeout(OPEN_TIMEOUT, async {
            let mut s = opener.open().await.ok()?;
            s.write_all(&[kind]).await.ok()?;
            s.flush().await.ok()?;
            Some(s)
        })
        .await
        .ok()?
    }

    /// 直连 HTTPS：此处能看到请求与响应内容，只在内存中经过。
    async fn direct(&self, req: Request<Incoming>) -> Reply {
        let too_big = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
            .is_some_and(|n| n > MAX_BODY);
        if too_big {
            drain(req.into_body()).await;
            return text(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large");
        }
        let Ok(permit) = self.forwards.clone().try_acquire_owned() else {
            return busy();
        };
        let Some(stream) = self.open(STREAM_DIRECT).await else {
            return offline();
        };
        let (mut parts, body) = req.into_parts();
        strip(&mut parts.headers);
        let path = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .parse();
        let Ok(uri) = path else { return offline() };
        parts.uri = uri;
        parts.version = hyper::Version::HTTP_11;
        parts.extensions.clear();
        let req = Request::from_parts(parts, Limited::new(body, MAX_BODY).boxed());
        let Ok((mut send, conn)) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        else {
            return offline();
        };
        tokio::spawn(async move {
            let _ = timeout(DIRECT_TIMEOUT, conn).await;
            drop(permit);
        });
        let Ok(Ok(reply)) = timeout(DIRECT_TIMEOUT, send.send_request(req)).await else {
            return offline();
        };
        let (mut parts, body) = reply.into_parts();
        strip(&mut parts.headers);
        Response::from_parts(parts, body.boxed())
    }

    async fn device(self: Arc<Self>, up: OnUpgrade, permit: OwnedSemaphorePermit) {
        let Ok(Ok(up)) = timeout(vault_tunnel::HANDSHAKE_TIMEOUT, up).await else {
            return;
        };
        let mut io = TokioIo::new(up);
        let Ok(proven) = handshake::challenge(&mut io, &self.config.host).await else {
            return;
        };
        let verdict = match &proven {
            Some(p) => self.admit(p),
            None => Verdict::Rejected,
        };
        let sent = timeout(OPEN_TIMEOUT, frame::send(&mut io, &verdict)).await;
        drop(permit);
        let (Some(p), Verdict::Accepted, Ok(Ok(()))) = (proven, verdict, sent) else {
            log("device_rejected");
            return;
        };
        let (opener, drive) = mux::opener(io);
        let (kick, kicked) = oneshot::channel();
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        {
            let mut slot = self.online();
            // 答复与登记之间可能已被别的设备接管
            if self.config.state.current() != Some(p.key) {
                return;
            }
            let old = slot.replace(Online {
                id,
                key: p.key,
                direct: p.direct,
                opener: opener.clone(),
                kick,
            });
            if let Some(old) = old {
                let _ = old.kick.send(old.key != p.key);
            }
        }
        log("device_online");
        tokio::select! {
            _ = drive => {}
            _ = self.control(p.key, opener, kicked) => {}
        }
        let mut slot = self.online();
        if slot.as_ref().is_some_and(|o| o.id == id) {
            *slot = None;
        }
        drop(slot);
        log("device_offline");
    }

    /// 持锁核对身份；接管成功时当场断开旧设备。
    fn admit(&self, p: &handshake::Proven) -> Verdict {
        let mut slot = self.online();
        let verdict = self.config.state.admit(p);
        if verdict == Verdict::Accepted
            && slot.as_ref().is_some_and(|o| o.key != p.key)
            && let Some(old) = slot.take()
        {
            let _ = old.kick.send(true);
            log("device_replaced");
        }
        verdict
    }

    /// 心跳、取代通知，并留意管理员用命令行做的重置。返回即断开隧道。
    async fn control(&self, key: PublicKey, opener: Opener, mut kicked: oneshot::Receiver<bool>) {
        let Ok(mut s) = opener.open().await else {
            return;
        };
        if s.write_all(&[STREAM_CONTROL, PING]).await.is_err() {
            return;
        }
        let mut seen = Instant::now();
        let mut pinged = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        let mut buf = [0; 64];
        loop {
            tokio::select! {
                superseded = &mut kicked => {
                    if superseded == Ok(true) {
                        let notice = async {
                            s.write_all(&[SUPERSEDED]).await?;
                            s.flush().await?;
                            // 等对方读到后自己断开
                            while s.read(&mut buf).await? > 0 {}
                            std::io::Result::Ok(())
                        };
                        let _ = timeout(Duration::from_millis(500), notice).await;
                    }
                    return;
                }
                n = s.read(&mut buf) => {
                    if !matches!(n, Ok(1..)) {
                        return;
                    }
                    seen = Instant::now();
                }
                _ = tick.tick() => {
                    if seen.elapsed() > PING_TIMEOUT || self.config.state.current() != Some(key) {
                        return;
                    }
                    if pinged.elapsed() >= PING_INTERVAL {
                        pinged = Instant::now();
                        let ping = async { s.write_all(&[PING]).await?; s.flush().await };
                        if !matches!(timeout(OPEN_TIMEOUT, ping).await, Ok(Ok(()))) {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// 读掉并丢弃超限的请求体，否则反向代理写到一半被断开，会把 413 变成 502。
async fn drain(mut body: Incoming) {
    let mut left = 1024 * 1024usize;
    let _ = timeout(OPEN_TIMEOUT, async {
        while let Some(Ok(f)) = body.frame().await {
            let n = f.data_ref().map_or(0, Bytes::len);
            if n > left {
                break;
            }
            left -= n;
        }
    })
    .await;
}

/// 桥接流量：内层是双方之间的 TLS，这里原样搬运。
async fn splice(up: OnUpgrade, mut stream: Stream, permit: OwnedSemaphorePermit) {
    let _ = timeout(BRIDGE_TIMEOUT, async {
        if let Ok(up) = up.await {
            let _ = copy_bidirectional(&mut TokioIo::new(up), &mut stream).await;
        }
    })
    .await;
    drop(permit);
}

/// 开始服务。返回实际监听地址与须一直运行的 future。
pub async fn bind(
    listen: SocketAddr,
    config: Config,
) -> std::io::Result<(SocketAddr, impl Future<Output = ()> + Send)> {
    let listener = TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let relay = Arc::new(Relay {
        limiter: Limiter::new(config.per_source, config.total),
        config,
        online: Mutex::default(),
        next: AtomicU64::new(0),
        forwards: Arc::new(Semaphore::new(MAX_FORWARDS)),
        handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
    });
    log("started");
    Ok((addr, accept(listener, relay)))
}

async fn accept(listener: TcpListener, relay: Arc<Relay>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else {
            return;
        };
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = tcp.set_nodelay(true);
        let relay = relay.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let relay = relay.clone();
                async move { Ok::<_, Infallible>(relay.handle(req).await) }
            });
            let mut settings = http1::Builder::new();
            settings
                .max_buf_size(16 * 1024)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(15));
            let conn = settings
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades();
            // 升级后的连接由各自的任务持有，不受此限
            let _ = timeout(Duration::from_secs(300), conn).await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_headers_do_not_reach_the_device() {
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("connection", "close, X-Hop"),
            ("x-hop", "1"),
            ("x-forwarded-for", "192.0.2.1"),
            ("x-forwarded-proto", "https"),
            ("x-real-ip", "192.0.2.1"),
            ("authorization", "Bearer fake"),
            ("x-auth-code", "FAKE"),
            ("mcp-method", "tools/list"),
        ] {
            h.insert(k, v.parse().unwrap());
        }
        h.append(
            "x-forwarded-for",
            "198.51.100.9, 203.0.113.7".parse().unwrap(),
        );
        assert_eq!(source(&h), "203.0.113.7");
        strip(&mut h);
        let mut left: Vec<_> = h.keys().map(|k| k.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["authorization", "mcp-method", "x-auth-code"]);
    }
}
