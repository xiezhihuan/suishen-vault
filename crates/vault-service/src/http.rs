use crate::{
    Engine, ServiceError,
    engine::{BAD, OFF, Result, charge},
    mcp::{self, Backend, Operation, Tools},
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
    convert::Infallible,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
use tower_service::Service;
use vault_core::{ExposureScope, search::ClientId};

const BUSY: ServiceError = ServiceError(503, "port_in_use");
const MAX_BODY: usize = 64 * 1024;
type Reply = Response<Full<Bytes>>;
/// App 与服务共用的 Engine。持有其锁时不得再调用 [`ServiceHandle`] 的方法。
pub type SharedEngine = Arc<Mutex<Engine>>;
struct Session {
    /// 关闭时取走，之后的请求一律拒绝，密库也不再被服务占用。
    engine: Mutex<Option<SharedEngine>>,
    started: Instant,
    wall: SystemTime,
    ttl: Option<Duration>,
    failed: Mutex<std::collections::HashMap<IpAddr, Vec<i64>>>,
    general: Mutex<std::collections::HashMap<ClientId, Vec<i64>>>,
}
impl Session {
    fn expired(&self) -> bool {
        self.ttl.is_some_and(|t| {
            self.started.elapsed() >= t || self.wall.elapsed().map_or(true, |d| d >= t)
        })
    }
    fn close(&self) {
        // 锁即使因其他线程 panic 而中毒，也必须能关闭。
        let mut slot = self.engine.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(shared) = slot.take() {
            shared
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .end_service();
        }
    }
    fn with<T>(&self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        if self.expired() {
            self.close();
            return Err(OFF);
        }
        let slot = self.engine.lock().map_err(|_| OFF)?;
        let shared = slot.as_ref().ok_or(OFF)?;
        f(&mut *shared.lock().map_err(|_| OFF)?)
    }
    fn identify(&self, headers: &HeaderMap, ip: IpAddr) -> Result<ClientId> {
        let token = single(headers, "authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        let result = self.with(|e| e.authenticate(token));
        let now = self.started.elapsed().as_millis() as i64;
        if let Ok(c) = result {
            charge(
                self.general.lock().map_err(|_| OFF)?.entry(c).or_default(),
                now,
                240,
            )?;
        } else {
            // 回环来源按地址族合并，不能通过轮换 127/8 填满来源表。
            let source = if ip.is_ipv4() {
                IpAddr::from([127, 0, 0, 1])
            } else {
                IpAddr::from(std::net::Ipv6Addr::LOCALHOST)
            };
            charge(
                self.failed
                    .lock()
                    .map_err(|_| OFF)?
                    .entry(source)
                    .or_default(),
                now,
                30,
            )?;
        }
        result
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
        if self.session().is_ok() {
            ExposureScope::Loopback
        } else {
            ExposureScope::Closed
        }
    }
    fn session(&self) -> Result<Arc<Session>> {
        let guard = self.running.lock().map_err(|_| OFF)?;
        guard
            .as_ref()
            .filter(|r| !r.task.is_finished() && !r.session.expired())
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
        if self.session().is_ok() {
            return Err(OFF);
        }
        // 先收尾已到期的上一次会话，否则它的关闭动作会影响新会话。
        self.close();
        let v4 = TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|_| BUSY)?;
        let port = v4.local_addr().map_err(|_| OFF)?.port();
        let v6 = TcpListener::bind(("::1", port)).await.map_err(|_| BUSY)?;
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
            failed: Mutex::default(),
            general: Mutex::default(),
        });
        let task = tokio::spawn(listen(v4, v6, port, session.clone()));
        *slot = Some(Running { session, task });
        Ok(port)
    }
}
async fn listen(v4: TcpListener, v6: TcpListener, port: u16, session: Arc<Session>) {
    let mut connections = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        let next = tokio::select! {
            a=v4.accept()=>a,b=v6.accept()=>b,
            _=tick.tick()=>{if session.with(|e|{e.sweep();Ok(())}).is_err(){break}continue},
            _=connections.join_next(), if !connections.is_empty()=>continue,
        };
        let Ok((stream, peer)) = next else { break };
        if connections.len() >= 32 {
            continue;
        }
        let session = session.clone();
        connections.spawn(async move {
            let svc = service_fn(move |req| {
                let session = session.clone();
                async move {
                    let mut reply = route(req, session, peer.ip(), port)
                        .await
                        .unwrap_or_else(error);
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
        });
    }
    session.close();
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
}
impl Backend for LocalBackend {
    async fn execute(&self, op: Operation) -> Result<String> {
        let c = self.client;
        let s = &self.session;
        let value = match op {
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
async fn route(
    req: Request<Incoming>,
    session: Arc<Session>,
    ip: IpAddr,
    port: u16,
) -> Result<Reply> {
    let h = req.headers();
    let hosts = [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ];
    if !single(h, "host").is_some_and(|v| hosts.iter().any(|s| s == v))
        || req.uri().authority().is_some()
    {
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
    match (method.as_str(), path.as_str()) {
        ("GET", "/health") | ("POST", "/mcp" | "/v1/search" | "/v1/requests") => {}
        ("GET", _) if handle.is_some() => {}
        (_, _) if handle.is_some() => return Err(ServiceError(405, "method_not_allowed")),
        (_, "/mcp") => return Err(ServiceError(405, "method_not_allowed")),
        _ => return Err(ServiceError(404, "not_found")),
    }
    let c = session.identify(h, ip)?;
    let local = LocalBackend {
        session: session.clone(),
        client: c,
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
    let op = if path == "/v1/search" {
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
