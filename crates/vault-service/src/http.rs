use crate::remote::Remote;
use crate::{
    Engine, ServiceError,
    engine::{BAD, OFF, Origin, Result, charge},
    mcp::{self, Backend, Operation, Tools},
    tunnel::{self, TunnelState},
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    HeaderMap, Method, Request, Response,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tower_service::Service;
use vault_core::{ExposureScope, search::ClientId};
use vault_tunnel::{PublicKey, tls::DEVICE_HOST};

const BUSY: ServiceError = ServiceError(503, "port_in_use");
const MAX_BODY: usize = 64 * 1024;
type Reply = Response<Full<Bytes>>;
/// App 与服务共用的 Engine。持有其锁时不得再调用 [`ServiceHandle`] 的方法。
pub type SharedEngine = Arc<Mutex<Engine>>;
/// 公网档的选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Public {
    /// 允许直连 HTTPS：跳板主机能看到令牌与取到的明文。
    pub direct: bool,
}
/// 连接的来路，决定主机名、鉴权与限流。
#[derive(Clone)]
pub(crate) enum Via {
    Loopback(IpAddr, u16),
    Direct(Arc<str>),
    Bridge(PublicKey),
}
impl Via {
    fn origin(&self) -> Origin {
        match self {
            Self::Loopback(..) => Origin::Loopback,
            Self::Direct(_) => Origin::Direct,
            Self::Bridge(k) => Origin::Bridge(*k),
        }
    }
    fn public(&self) -> bool {
        !matches!(self, Self::Loopback(..))
    }
    fn limits(&self) -> &'static Limits {
        if self.public() {
            &PUBLIC_LIMITS
        } else {
            &LOCAL_LIMITS
        }
    }
    fn host_ok(&self, host: &str) -> bool {
        match self {
            Self::Loopback(_, port) => ["127.0.0.1", "localhost", "[::1]"]
                .iter()
                .any(|h| host == format!("{h}:{port}")),
            Self::Direct(h) => host == &**h,
            Self::Bridge(_) => host == DEVICE_HOST,
        }
    }
}
/// 每分钟上限。公网下更严。
struct Limits {
    general: usize,
    failed: usize,
    search: usize,
    request: usize,
    secret: usize,
}
const LOCAL_LIMITS: Limits = Limits {
    general: 240,
    failed: 30,
    search: 60,
    request: 60,
    secret: 60,
};
/// 来源地址经过跳板后不可信，所以未认证请求全部算作一个来源。
const PUBLIC_LIMITS: Limits = Limits {
    general: 60,
    failed: 10,
    search: 5,
    request: 2,
    secret: 5,
};
pub(crate) struct Session {
    /// 关闭时取走，之后的请求一律拒绝，密库也不再被服务占用。
    engine: Mutex<Option<SharedEngine>>,
    started: Instant,
    wall: SystemTime,
    ttl: Option<Duration>,
    public: Option<Public>,
    closed: AtomicBool,
    tunnel: Mutex<TunnelState>,
    /// 未认证请求。`None` 为公网，其余按回环地址族。
    failed: Mutex<HashMap<Option<IpAddr>, Vec<i64>>>,
    general: Mutex<HashMap<(ClientId, &'static str), Vec<i64>>>,
}
impl Session {
    fn expired(&self) -> bool {
        self.ttl.is_some_and(|t| {
            self.started.elapsed() >= t || self.wall.elapsed().map_or(true, |d| d >= t)
        })
    }
    pub(crate) fn set_tunnel(&self, state: TunnelState) {
        *self.tunnel.lock().unwrap_or_else(|e| e.into_inner()) = state;
    }
    fn tunnel(&self) -> TunnelState {
        *self.tunnel.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// 已关闭或已到期。监听任务可能还要片刻才结束。
    fn over(&self) -> bool {
        self.closed.load(Ordering::SeqCst) || self.expired()
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // 锁即使因其他线程 panic 而中毒，也必须能关闭。
        let mut slot = self.engine.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(shared) = slot.take() {
            shared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .end_service();
        }
    }
    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        if self.expired() {
            self.close();
            return Err(OFF);
        }
        let slot = self.engine.lock().map_err(|_| OFF)?;
        let shared = slot.as_ref().ok_or(OFF)?;
        f(&mut *shared.lock().map_err(|_| OFF)?)
    }
    /// 已认证客户端的某类请求计一次。
    fn charge(&self, client: ClientId, kind: &'static str, limit: usize) -> Result<()> {
        let now = self.started.elapsed().as_millis() as i64;
        charge(
            self.general
                .lock()
                .map_err(|_| OFF)?
                .entry((client, kind))
                .or_default(),
            now,
            limit,
        )
    }
    fn identify(&self, headers: &HeaderMap, via: &Via) -> Result<ClientId> {
        let token = single(headers, "authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let result = self.with(|e| e.authenticate(token, via.origin()));
        match result {
            Ok(c) => self.charge(c, "all", via.limits().general)?,
            // 有效令牌不受他人失败次数影响
            Err(_) => self.charge_failed(via)?,
        }
        result
    }
    fn charge_failed(&self, via: &Via) -> Result<()> {
        // 回环来源按地址族合并，不能通过轮换 127/8 填满来源表。
        let source = match via {
            Via::Loopback(ip, _) if ip.is_ipv4() => Some(IpAddr::from([127, 0, 0, 1])),
            Via::Loopback(..) => Some(IpAddr::from(std::net::Ipv6Addr::LOCALHOST)),
            _ => None,
        };
        charge(
            self.failed
                .lock()
                .map_err(|_| OFF)?
                .entry(source)
                .or_default(),
            self.started.elapsed().as_millis() as i64,
            via.limits().failed,
        )
    }
}
struct Running {
    session: Arc<Session>,
    task: JoinHandle<()>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.session.close();
        self.task.abort();
    }
}
#[derive(Default)]
pub struct ServiceHandle {
    running: Mutex<Option<Running>>,
}
impl ServiceHandle {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn scope(&self) -> ExposureScope {
        match self.session() {
            Ok(s) if s.public.is_some() => ExposureScope::Public,
            Ok(_) => ExposureScope::Loopback,
            Err(_) => ExposureScope::Closed,
        }
    }
    /// 隧道状态。被取代后服务已关闭，仍保留该提示直到下次开启。
    pub fn tunnel(&self) -> TunnelState {
        let guard = self.running.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref().map(|r| r.session.tunnel()) {
            Some(TunnelState::Superseded) => TunnelState::Superseded,
            Some(s) if self.alive(guard.as_ref()) => s,
            _ => TunnelState::Off,
        }
    }
    fn alive(&self, r: Option<&Running>) -> bool {
        r.is_some_and(|r| !r.task.is_finished() && !r.session.over())
    }
    /// 当前公网档是否允许直连。
    pub fn direct(&self) -> bool {
        self.session()
            .is_ok_and(|s| s.public.is_some_and(|p| p.direct))
    }
    fn session(&self) -> Result<Arc<Session>> {
        let guard = self.running.lock().map_err(|_| OFF)?;
        guard
            .as_ref()
            .filter(|r| !r.task.is_finished() && !r.session.over())
            .map(|r| r.session.clone())
            .ok_or(OFF)
    }
    pub fn local<T>(&self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        self.session()?.with(f)
    }
    pub fn remaining_seconds(&self) -> Option<u64> {
        let s = self.session().ok()?;
        s.ttl.map(|t| {
            t.saturating_sub(s.started.elapsed().max(s.wall.elapsed().unwrap_or(t)))
                .as_secs()
        })
    }
    pub fn close(&self) {
        if let Ok(mut slot) = self.running.lock() {
            slot.take();
        }
    }
    /// 两个回环端口全部绑定成功才开始服务。0 只用于测试时选择空闲端口。
    pub async fn open_loopback(
        &self,
        engine: Engine,
        port: u16,
        ttl: Option<Duration>,
    ) -> Result<u16> {
        self.open_shared(Arc::new(Mutex::new(engine)), port, ttl)
            .await
    }
    /// 与界面共用 Engine。
    pub async fn open_shared(
        &self,
        engine: SharedEngine,
        port: u16,
        ttl: Option<Duration>,
    ) -> Result<u16> {
        self.open(engine, port, ttl, None).await
    }
    /// `public` 有值时另外连到跳板。端口绑定成功、跳板已登记才开始服务。
    pub async fn open(
        &self,
        engine: SharedEngine,
        port: u16,
        ttl: Option<Duration>,
        public: Option<Public>,
    ) -> Result<u16> {
        if self.session().is_ok() {
            return Err(OFF);
        }
        // 先收尾已到期的上一次会话，否则它的关闭动作会影响新会话。
        self.close();
        let remote = match public {
            Some(_) => Some(engine.lock().map_err(|_| OFF)?.remote()?),
            None => None,
        };
        let v4 = bind(("127.0.0.1", port)).await?;
        let port = v4.local_addr().map_err(|_| OFF)?.port();
        let v6 = bind(("::1", port)).await?;
        let mut slot = self.running.lock().map_err(|_| OFF)?;
        if slot.is_some() {
            return Err(OFF);
        }
        engine.lock().map_err(|_| OFF)?.begin_service()?;
        let session = Arc::new(Session {
            engine: Mutex::new(Some(engine)),
            started: Instant::now(),
            wall: SystemTime::now(),
            ttl,
            public,
            closed: AtomicBool::new(false),
            tunnel: Mutex::default(),
            failed: Mutex::default(),
            general: Mutex::default(),
        });
        let dial = remote.zip(public).map(|(r, p)| (r, p.direct));
        let task = tokio::spawn(listen(v4, v6, port, session.clone(), dial));
        *slot = Some(Running { session, task });
        Ok(port)
    }
}
/// 刚关闭的上一次会话可能还没放开端口，短暂重试。
async fn bind(addr: (&str, u16)) -> Result<TcpListener> {
    for _ in 0..20 {
        if let Ok(l) = TcpListener::bind(addr).await {
            return Ok(l);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(BUSY)
}
async fn listen(
    v4: TcpListener,
    v6: TcpListener,
    port: u16,
    session: Arc<Session>,
    dial: Option<(Remote, bool)>,
) {
    // 丢弃这两个集合会立即中断其中所有连接，包括隧道
    let mut tunnel = JoinSet::new();
    let mut connections = JoinSet::new();
    if let Some((remote, direct)) = dial {
        tunnel.spawn(tunnel::run(session.clone(), remote, direct));
    }
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        let next = tokio::select! {
            a=v4.accept()=>a,b=v6.accept()=>b,
            _=tick.tick()=>{if session.with(|e|{e.sweep();e.pairing_sweep();Ok(())}).is_err(){break}continue},
            _=connections.join_next(), if !connections.is_empty()=>continue,
            // 只有被取代或无法建立时才会返回：整个服务一起关闭，不留半开状态
            _=tunnel.join_next(), if !tunnel.is_empty()=>break,
        };
        let Ok((stream, peer)) = next else { break };
        if connections.len() >= 32 {
            continue;
        }
        connections.spawn(serve(
            stream,
            session.clone(),
            Via::Loopback(peer.ip(), port),
        ));
    }
    session.close();
}
/// 在一条字节流上提供服务。
pub(crate) async fn serve<S>(stream: S, session: Arc<Session>, via: Via)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let svc = service_fn(move |req| {
        let session = session.clone();
        let via = via.clone();
        async move {
            let mut reply = route(req, session, &via).await.unwrap_or_else(error);
            let h = reply.headers_mut();
            h.insert("cache-control", "no-store".parse().unwrap());
            h.insert("x-content-type-options", "nosniff".parse().unwrap());
            Ok::<_, Infallible>(reply)
        }
    });
    let mut settings = http1::Builder::new();
    settings
        .keep_alive(false)
        .max_buf_size(16 * 1024)
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(15));
    let _ = tokio::time::timeout(
        Duration::from_secs(60),
        settings.serve_connection(TokioIo::new(stream), svc),
    )
    .await;
}
fn single<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    let mut items = h.get_all(k).iter();
    let first = items.next()?;
    (items.next().is_none())
        .then(|| first.to_str().ok())
        .flatten()
}
fn reply(status: u16, b: Bytes) -> Reply {
    let mut r = Response::new(Full::new(b));
    *r.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    r.headers_mut().insert(
        "content-type",
        "application/json; charset=utf-8".parse().unwrap(),
    );
    r
}
fn error(e: ServiceError) -> Reply {
    let mut r = reply(e.0, Bytes::from(json!({"error":e.1}).to_string()));
    if e.0 == 401 {
        r.headers_mut().insert(
            "www-authenticate",
            "Bearer realm=\"suishen-vault\"".parse().unwrap(),
        );
    }
    r
}
fn request_path(path: &str) -> Option<(&str, bool)> {
    let p = path.strip_prefix("/v1/requests/")?;
    let id = p.strip_suffix("/secret").unwrap_or(p);
    mcp::valid_id(id).then_some((id, p != id))
}
fn get_secret(
    session: &Session,
    client: ClientId,
    req: &hyper::http::request::Parts,
) -> Result<Bytes> {
    if req.method != Method::GET {
        return Err(ServiceError(405, "method_not_allowed"));
    }
    if req.uri.query().is_some() {
        return Err(ServiceError(400, "query_not_allowed"));
    }
    let (id, true) = request_path(req.uri.path()).ok_or(BAD)? else {
        return Err(BAD);
    };
    let h = &req.headers;
    // 带了非法或重复的请求头也算一次错误。
    if ["purpose", "sec-purpose", "x-purpose"]
        .iter()
        .any(|name| h.contains_key(*name))
    {
        return Err(ServiceError(400, "prefetch_not_allowed"));
    }
    let code = h
        .contains_key("x-auth-code")
        .then(|| single(h, "x-auth-code").unwrap_or(""));
    session
        .with(|e| e.redeem(client, id, code))
        .map(Bytes::from_owner)
}
#[derive(Clone)]
struct LocalBackend {
    session: Arc<Session>,
    client: ClientId,
    limits: &'static Limits,
}
impl LocalBackend {
    fn charge(&self, op: &Operation) -> Result<()> {
        let (kind, limit) = match op {
            Operation::Propose(_) => ("draft", self.limits.request),
            Operation::Search(_) => ("search", self.limits.search),
            Operation::Request { .. } => ("request", self.limits.request),
            Operation::Secret(..) => ("secret", self.limits.secret),
            Operation::Status(..) => return Ok(()),
        };
        self.session.charge(self.client, kind, limit)
    }
}
impl Backend for LocalBackend {
    async fn execute(&self, op: Operation) -> Result<String> {
        let c = self.client;
        let s = &self.session;
        self.charge(&op)?;
        let value = match op {
            Operation::Propose(p) => s.with(|e| e.propose(c, p))?,
            Operation::Search(q) => s.with(|e| e.search(c, &q))?,
            Operation::Request {
                item_ref,
                fields,
                reason,
            } => s.with(|e| e.request(c, &item_ref, fields, &reason))?,
            Operation::Status(id, wait) => {
                let start = Instant::now();
                loop {
                    let state = s.with(|e| e.status(c, &id))?;
                    if state["state"] != "pending"
                        || start.elapsed() >= Duration::from_secs(wait.into())
                    {
                        break state;
                    }
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
            Operation::Secret(id, code) => {
                // 将已认证的客户端身份传给进程内 GET 处理器，不重新解析地址或向外发送令牌。
                let request = Request::get(format!("/v1/requests/{id}/secret"))
                    .header(
                        "x-auth-code",
                        code.parse()
                            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("")),
                    )
                    .body(())
                    .map_err(|_| BAD)?;
                let bytes = get_secret(s, c, &request.into_parts().0)?;
                return String::from_utf8(bytes.to_vec()).map_err(|_| OFF);
            }
        };
        Ok(value.to_string())
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBody {
    secret: String,
    label: String,
}
/// 桥接配对：此时还没有令牌，身份由内层 TLS 的公钥证明。
async fn pair(
    req: Request<Incoming>,
    session: &Session,
    peer: PublicKey,
    via: &Via,
) -> Result<Reply> {
    let body = Limited::new(req.into_body(), 1024)
        .collect()
        .await
        .map_err(|_| ServiceError(413, "body_too_large"))?
        .to_bytes();
    let b: PairBody = serde_json::from_slice(&body).map_err(|_| BAD)?;
    let secret = zeroize::Zeroizing::new(b.secret);
    let result = session.with(|e| e.pair(peer, &secret, &b.label));
    if result.is_err() {
        session.charge_failed(via)?;
    }
    Ok(reply(200, Bytes::from(result?.to_string())))
}
async fn route(req: Request<Incoming>, session: Arc<Session>, via: &Via) -> Result<Reply> {
    let h = req.headers();
    if !single(h, "host").is_some_and(|v| via.host_ok(v)) || req.uri().authority().is_some() {
        return Err(ServiceError(421, "invalid_host"));
    }
    if h.contains_key("origin") {
        return Err(ServiceError(403, "invalid_origin"));
    }
    if req.uri().query().is_some() {
        return Err(ServiceError(400, "query_not_allowed"));
    }
    let path = req.uri().path().to_owned();
    let method = req.method().clone();
    let handle = request_path(&path);
    if let (Via::Bridge(peer), "POST", "/v1/pair") = (via, method.as_str(), path.as_str()) {
        return pair(req, &session, *peer, via).await;
    }
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") | ("POST", "/mcp" | "/v1/drafts" | "/v1/search" | "/v1/requests") => {}
        ("GET", _) if handle.is_some() => {}
        (_, _) if handle.is_some() => return Err(ServiceError(405, "method_not_allowed")),
        (_, "/mcp") => return Err(ServiceError(405, "method_not_allowed")),
        _ => return Err(ServiceError(404, "not_found")),
    }
    let c = session.identify(h, via)?;
    let local = LocalBackend {
        session: session.clone(),
        client: c,
        limits: via.limits(),
    };
    let (parts, body) = req.into_parts();
    let body = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .map_err(|_| ServiceError(413, "body_too_large"))?
        .to_bytes();
    if method == Method::GET {
        if !body.is_empty() {
            return Err(BAD);
        }
        if path == "/health" {
            return Ok(reply(200, Bytes::from_static(br#"{"status":"ok"}"#)));
        }
        let (id, secret) = handle.ok_or(BAD)?;
        if secret {
            session.charge(c, "secret", via.limits().secret)?;
            return match get_secret(&session, c, &parts) {
                Err(ServiceError(410, "gone")) => {
                    let state = session.with(|e| e.status(c, id))?;
                    Ok(reply(
                        410,
                        Bytes::from(json!({"error":"gone","state":state["state"]}).to_string()),
                    ))
                }
                result => Ok(reply(200, result?)),
            };
        }
        return Ok(reply(
            200,
            Bytes::from(local.execute(Operation::Status(id.into(), 0)).await?),
        ));
    }
    if !single(&parts.headers, "content-type").is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"))
    }) {
        return Err(ServiceError(415, "content_type"));
    }
    if path == "/mcp" {
        // SDK 的诊断可能包含输入，向外只返回白名单错误。也不把 Bearer 传入 SDK。
        let mut req = Request::from_parts(parts, Full::new(body));
        req.headers_mut().remove("authorization");
        // 主机名已在上面按来路核对过，SDK 只认回环名
        if via.public() {
            req.headers_mut()
                .insert("host", hyper::header::HeaderValue::from_static("localhost"));
        }
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true);
        let mut svc: StreamableHttpService<_, LocalSessionManager> = StreamableHttpService::new(
            move || Ok(Tools(local.clone())),
            Default::default(),
            config,
        );
        let response = svc.call(req).await.map_err(|_| OFF)?;
        let (parts, b) = response.into_parts();
        let data = b.collect().await.map_err(|_| OFF)?.to_bytes();
        if !parts.status.is_success() {
            let rpc = serde_json::from_slice::<Value>(&data).ok();
            let code = rpc
                .as_ref()
                .and_then(|v| v["error"]["code"].as_i64())
                .unwrap_or(-32600);
            let id = rpc
                .as_ref()
                .and_then(|v| v.get("id"))
                .cloned()
                .unwrap_or(Value::Null);
            return Ok(reply(
                parts.status.as_u16(),
                Bytes::from(
                    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":"协议请求无效"}})
                        .to_string(),
                ),
            ));
        }
        return Ok(Response::from_parts(parts, Full::new(data)));
    }
    let op = if path == "/v1/drafts" {
        Operation::Propose(serde_json::from_slice(&body).map_err(|_| BAD)?)
    } else if path == "/v1/search" {
        let q: mcp::Search = serde_json::from_slice(&body).map_err(|_| BAD)?;
        Operation::Search(q.query)
    } else {
        let a: mcp::Access = serde_json::from_slice(&body).map_err(|_| BAD)?;
        Operation::Request {
            item_ref: a.item_ref,
            fields: a.fields,
            reason: a.reason,
        }
    };
    Ok(reply(200, Bytes::from(local.execute(op).await?)))
}
