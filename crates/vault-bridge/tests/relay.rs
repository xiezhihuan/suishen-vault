//! 公网端到端：设备、跳板、桥接三方真实联通。只用假数据。
//!
//! 平时用进程内跳板，前面隔一个会录下全部字节、可随时断开的代理。
//! `docker_*` 用 scripts/test-relay.mjs 起的容器：跳板 + Caddy 或 Nginx，tcpdump 抓包。
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, ChildStdout, Command},
    task::JoinSet,
};
use vault_core::{
    Auth, ExposureScope, SecretString, Setup,
    model::{AiField, ItemDraft, ItemKind},
};
use vault_relay::State;
use vault_service::{
    Access, Engine, LocalApproval, Public, ServiceHandle, SharedEngine, TunnelState, claim_relay,
};
use vault_tunnel::{
    BRIDGE_PATH, BRIDGE_PROTOCOL, DEVICE_PATH, DEVICE_PROTOCOL, Endpoint, Identity, PairCode, dial,
    handshake::{self, Verdict},
};

const PW: &str = "fake-master-鲸鱼-0001";
const SECRET: &str = "Fake-Violet-Secret-7172";
const USER: &str = "fake-oriole-account-1891";
const QUERY: &str = "Cassiopeia";
const REASON: &str = "Fake-Reason-Thistle-5521";

// ---- 跳板环境 ----

/// 录下流经的全部字节，可断开。
#[derive(Default)]
struct Tap {
    seen: Mutex<Vec<u8>>,
    cut: std::sync::atomic::AtomicBool,
    accepted: std::sync::atomic::AtomicUsize,
    links: Mutex<JoinSet<()>>,
}

async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    tap: Arc<Tap>,
) {
    let mut buf = vec![0; 16 * 1024];
    while let Ok(n @ 1..) = from.read(&mut buf).await {
        tap.seen.lock().unwrap().extend_from_slice(&buf[..n]);
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

async fn tap_loop(listener: TcpListener, target: SocketAddr, tap: Arc<Tap>) {
    use std::sync::atomic::Ordering::SeqCst;
    while let Ok((a, _)) = listener.accept().await {
        tap.accepted.fetch_add(1, SeqCst);
        if tap.cut.load(SeqCst) {
            continue;
        }
        let Ok(b) = TcpStream::connect(target).await else {
            continue;
        };
        let (ar, aw) = a.into_split();
        let (br, bw) = b.into_split();
        let mut links = tap.links.lock().unwrap();
        links.spawn(pump(ar, bw, tap.clone()));
        links.spawn(pump(br, aw, tap.clone()));
    }
}

enum Kind {
    Local {
        tap: Arc<Tap>,
        state: State,
        _dir: tempfile::TempDir,
        _tasks: JoinSet<()>,
    },
    Docker {
        relay: String,
        proxy: String,
        capture: PathBuf,
    },
}

struct Env {
    url: String,
    ca: Option<String>,
    kind: Kind,
}

fn docker(args: &[&str]) -> String {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "docker {}：{}",
        args[0],
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

impl Env {
    async fn local() -> Self {
        Self::local_with(100_000).await
    }
    async fn local_with(per_source: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let state = State::new(dir.path());
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = front.local_addr().unwrap().to_string();
        let mut config = vault_relay::Config::new(host.clone(), state.clone());
        config.per_source = per_source;
        config.total = 500_000;
        let (addr, run) = vault_relay::bind("127.0.0.1:0".parse().unwrap(), config)
            .await
            .unwrap();
        let tap = Arc::new(Tap::default());
        let mut tasks = JoinSet::new();
        tasks.spawn(run);
        tasks.spawn(tap_loop(front, addr, tap.clone()));
        Self {
            url: format!("http://{host}"),
            ca: None,
            kind: Kind::Local {
                tap,
                state,
                _dir: dir,
                _tasks: tasks,
            },
        }
    }
    fn docker() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("缺少环境变量 {k}"));
        Self {
            url: get("SV_RELAY_URL"),
            ca: Some(std::fs::read_to_string(get("SV_RELAY_CA")).unwrap()),
            kind: Kind::Docker {
                relay: get("SV_RELAY_CONTAINER"),
                proxy: get("SV_PROXY_CONTAINER"),
                capture: get("SV_CAPTURE").into(),
            },
        }
    }
    fn endpoint(&self) -> Endpoint {
        Endpoint::parse(&self.url).unwrap()
    }
    fn code(&self) -> String {
        match &self.kind {
            Kind::Local { state, .. } => state.issue_code().unwrap().display().to_string(),
            Kind::Docker { relay, .. } => {
                let out = docker(&["exec", relay, "vault-relay", "pair-code"]);
                let line = out.lines().next().unwrap();
                line.split('：').nth(1).unwrap().trim().to_owned()
            }
        }
    }
    fn unpair(&self) {
        match &self.kind {
            Kind::Local { state, .. } => state.unpair().unwrap(),
            Kind::Docker { relay, .. } => {
                docker(&["exec", relay, "vault-relay", "unpair"]);
            }
        }
    }
    /// 当前登记的设备公钥，跳板管理员看得到。
    fn current_key(&self) -> String {
        match &self.kind {
            Kind::Local { state, .. } => hex::encode(state.current().unwrap()),
            Kind::Docker { relay, .. } => {
                let text = docker(&["exec", relay, "cat", "/var/lib/vault-relay/state.json"]);
                let v: Value = serde_json::from_str(&text).unwrap();
                v["current"].as_str().unwrap().to_owned()
            }
        }
    }
    fn cut(&self) {
        match &self.kind {
            Kind::Local { tap, .. } => {
                tap.cut.store(true, std::sync::atomic::Ordering::SeqCst);
                *tap.links.lock().unwrap() = JoinSet::new();
            }
            Kind::Docker { proxy, .. } => {
                docker(&["stop", "-t", "1", proxy]);
            }
        }
    }
    fn restore(&self) {
        match &self.kind {
            Kind::Local { tap, .. } => tap.cut.store(false, std::sync::atomic::Ordering::SeqCst),
            Kind::Docker { proxy, .. } => {
                docker(&["start", proxy]);
            }
        }
    }
    /// 到目前为止跳板收发的全部字节。
    async fn captured(&self) -> Vec<u8> {
        match &self.kind {
            Kind::Local { tap, .. } => tap.seen.lock().unwrap().clone(),
            Kind::Docker { capture, .. } => {
                // tcpdump -U 逐包落盘，留出写入时间
                tokio::time::sleep(Duration::from_secs(2)).await;
                std::fs::read(capture).unwrap()
            }
        }
    }
    /// 一次普通的 HTTPS 请求，相当于直连客户端。
    async fn http(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> (u16, hyper::HeaderMap, String) {
        let e = self.endpoint();
        let io = dial::connect(&e, self.ca.as_deref()).await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
            .await
            .unwrap();
        tokio::spawn(conn);
        let mut req = Request::builder().method(method).uri(path);
        if !headers.iter().any(|(k, _)| *k == "host") {
            req = req.header("host", e.authority());
        }
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let req = req.body(Full::new(Bytes::from(body.to_owned()))).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(20), send.send_request(req))
            .await
            .unwrap()
            .unwrap();
        let (parts, body) = r.into_parts();
        let data = body.collect().await.unwrap().to_bytes();
        (
            parts.status.as_u16(),
            parts.headers,
            String::from_utf8(data.to_vec()).unwrap(),
        )
    }
    async fn api(&self, token: &str, method: &str, path: &str, body: &str) -> (u16, String) {
        let bearer = format!("Bearer {token}");
        let h = [
            ("authorization", bearer.as_str()),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ];
        let (s, _, b) = self.http(method, path, &h, body).await;
        (s, b)
    }
    /// 各种外来请求，离线时必须得到逐字相同的答复。
    async fn probes(&self) -> Vec<(u16, Vec<(String, String)>, String)> {
        let mut out = Vec::new();
        let up = [
            ("connection", "Upgrade"),
            ("upgrade", BRIDGE_PROTOCOL),
            ("x", "1"),
        ];
        let auth = [("authorization", "Bearer 00"), ("x-auth-code", "00000000")];
        for (method, path, headers, body) in [
            ("GET", "/", &[][..], ""),
            ("GET", "/health", &auth[..], ""),
            ("POST", "/mcp", &auth[..], "{}"),
            ("POST", "/v1/search", &[][..], "{}"),
            (
                "GET",
                "/v1/requests/req_00000000000000000000000000000000/secret",
                &auth[..],
                "",
            ),
            ("GET", "/_relay", &[][..], ""),
            ("GET", DEVICE_PATH, &[][..], ""),
            ("GET", BRIDGE_PATH, &up[..], ""),
            ("DELETE", "/nothing/here", &[][..], ""),
        ] {
            let (s, h, b) = self.http(method, path, headers, body).await;
            // 日期与反向代理自己的头与是否有设备无关
            let h = h
                .iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "date" | "server" | "via" | "alt-svc" | "connection"
                    )
                })
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
                .collect();
            out.push((s, h, b));
        }
        out
    }
    async fn assert_offline(&self, when: &str) {
        for (s, h, b) in self.probes().await {
            assert_eq!(
                (s, b.as_str()),
                (503, r#"{"error":"unavailable"}"#),
                "{when}"
            );
            assert!(
                h.contains(&("cache-control".into(), "no-store".into())),
                "{when}"
            );
            assert_eq!(h.len(), 4, "{when} {h:?}");
        }
    }
}

// ---- 主设备 ----

struct Device {
    _dir: tempfile::TempDir,
    engine: SharedEngine,
    service: ServiceHandle,
}

impl Device {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(vault_core::SystemClock::default());
        let setup = Setup::begin(&PW.into()).unwrap();
        let key = setup.recovery_key();
        let answers = setup
            .challenge()
            .map(|i| key.expose().split('-').nth(i as usize).unwrap());
        let mut v = setup
            .confirm(&dir.path().join("test.svault"), answers, clock.clone())
            .unwrap();
        let mut item = ItemDraft::new(ItemKind::Login, QUERY);
        item.secrets.username = Some(USER.into());
        item.secrets.password = Some(SECRET.into());
        v.add(&item).unwrap();
        Self {
            _dir: dir,
            engine: Arc::new(Mutex::new(Engine::attach(v, clock).unwrap())),
            service: ServiceHandle::new(),
        }
    }
    fn with<T>(&self, f: impl FnOnce(&mut Engine) -> T) -> T {
        f(&mut self.engine.lock().unwrap())
    }
    async fn claim(&self, env: &Env, code: &str) -> Result<(), &'static str> {
        let claim = self
            .with(|e| {
                e.relay_begin(
                    &env.url,
                    env.ca.as_deref(),
                    code,
                    Auth::Password(&PW.into()),
                )
            })
            .map_err(|e| e.1)?;
        let claim = claim_relay(claim).await.map_err(|e| e.1)?;
        self.with(|e| e.relay_commit(claim)).map_err(|e| e.1)
    }
    async fn open(&self, direct: bool, ttl: Option<Duration>) -> Result<u16, &'static str> {
        self.service
            .open(self.engine.clone(), 0, ttl, Some(Public { direct }))
            .await
            .map_err(|e| e.1)
    }
    async fn wait(&self, state: TunnelState, secs: u64) {
        let start = Instant::now();
        while self.service.tunnel() != state {
            assert!(
                start.elapsed() < Duration::from_secs(secs),
                "等待 {state:?}，现在是 {:?}",
                self.service.tunnel()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    async fn online(env: &Env, direct: bool) -> Self {
        let d = Self::new();
        d.claim(env, &env.code()).await.unwrap();
        d.open(direct, None).await.unwrap();
        d.wait(TunnelState::Online, 15).await;
        // 设备得知已接受略早于跳板登记完成
        tokio::time::sleep(Duration::from_millis(100)).await;
        d
    }
    fn approve(&self, id: &str) -> SecretString {
        let r = self.with(|e| {
            e.approve(
                id,
                vec![AiField::Password],
                Auth::Password(&PW.into()),
                true,
            )
        });
        match r.unwrap() {
            LocalApproval::Code(c) => c,
            LocalApproval::View(_) => panic!("应出码"),
        }
    }
    fn client(&self, access: Access) -> String {
        self.with(|e| e.add_client_for("假客户端", vec![], access))
            .unwrap()
            .1
            .expose()
            .to_owned()
    }
    /// 用真实的 vault-bridge 可执行文件配对。
    async fn pair(&self) -> (Bridge, String) {
        let text = self
            .with(|e| e.pairing_begin("假桥接", vec![], Auth::Password(&PW.into())))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut child = bridge_command(&dir, &["pair", "codex"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(text.expose().as_bytes()).await.unwrap();
        drop(stdin);
        let start = Instant::now();
        let asked = loop {
            let info = self.with(|e| e.pairing_info());
            if info["state"] == "asked" {
                break info;
            }
            assert!(start.elapsed() < Duration::from_secs(20), "桥接没有连上");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        // 没有确认之前不会有新客户端
        let before = self.with(|e| e.clients().as_array().unwrap().len());
        self.with(|e| e.pairing_accept()).unwrap();
        assert_eq!(
            self.with(|e| e.clients().as_array().unwrap().len()),
            before + 1
        );
        let out = tokio::time::timeout(Duration::from_secs(20), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(out.status.success(), "{err}");
        // 两端显示同一个指纹；输出里没有令牌与配对密钥
        assert!(err.contains(asked["fingerprint"].as_str().unwrap()));
        let profile: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("codex-remote.json")).unwrap())
                .unwrap();
        let token = profile["token"].as_str().unwrap().to_owned();
        assert!(!err.contains(&token) && !err.contains(text.expose()));
        assert!(out.stdout.is_empty());
        assert_eq!(self.with(|e| e.pairing_info()), Value::Null);
        (Bridge::start(dir).await, token)
    }
}

// ---- 桥接 ----

fn bridge_command(dir: &tempfile::TempDir, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_vault-bridge"));
    c.args(args)
        .env("SUISHEN_BRIDGE_DIR", dir.path())
        .env("HOSTNAME", "fake-laptop")
        .kill_on_drop(true);
    c
}

struct Bridge {
    dir: tempfile::TempDir,
    _child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    next: u64,
}

impl Bridge {
    async fn start(dir: tempfile::TempDir) -> Self {
        let mut child = bridge_command(&dir, &["mcp", "codex", "remote"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut b = Self {
            dir,
            stdin: child.stdin.take().unwrap(),
            stdout: BufReader::new(child.stdout.take().unwrap()).lines(),
            _child: child,
            next: 1,
        };
        let r = b
            .rpc(
                "initialize",
                json!({"protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"fake","version":"1"}}),
            )
            .await;
        assert_eq!(r["result"]["serverInfo"]["name"], "suishen-vault");
        b.write(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await;
        b
    }
    async fn write(&mut self, v: &Value) {
        let line = format!("{v}\n");
        self.stdin.write_all(line.as_bytes()).await.unwrap();
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.write(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .await;
        loop {
            let line = tokio::time::timeout(Duration::from_secs(40), self.stdout.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            if v["id"] == id {
                return v;
            }
        }
    }
    /// 工具结果；业务错误为 `Err`。
    async fn tool(&mut self, name: &str, args: Value) -> Result<Value, String> {
        let r = self
            .rpc("tools/call", json!({"name":name,"arguments":args}))
            .await;
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        let v: Value = serde_json::from_str(text).unwrap();
        if r["result"]["isError"] == true {
            return Err(v["error"].as_str().unwrap().to_owned());
        }
        Ok(v)
    }
    async fn request(&mut self) -> String {
        let hits = self
            .tool("search_entries", json!({"query":QUERY}))
            .await
            .unwrap();
        let r = self
            .tool(
                "request_access",
                json!({"item_ref":hits["results"][0]["item_ref"],"fields":["password"],"reason":REASON}),
            )
            .await
            .unwrap();
        r["request_id"].as_str().unwrap().to_owned()
    }
    /// 搜索、申请、批准、取明文，返回用过的授权码。
    async fn full_flow(&mut self, d: &Device) -> String {
        let id = self.request().await;
        assert_eq!(
            self.tool("get_request_status", json!({"request_id":id}))
                .await
                .unwrap()["state"],
            "pending"
        );
        let code = d.approve(&id);
        let args = json!({"request_id":id,"code":code.expose()});
        let got = self.tool("get_secret", args.clone()).await.unwrap();
        assert_eq!(got["fields"], json!([{"name":"password","value":SECRET}]));
        assert_eq!(self.tool("get_secret", args).await.unwrap_err(), "gone");
        code.expose().to_owned()
    }
}

// ---- 场景 ----

fn contains(data: &[u8], marker: &str) -> bool {
    data.windows(marker.len()).any(|w| w == marker.as_bytes())
}

/// 离线答复统一；桥接全流程，跳板抓不到内容；直连作为对照，证明抓包有效。
/// AC-REL-01 AC-GET-01 AC-GET-03 AC-MCP-07
async fn scenario_both_modes_and_capture(env: &Env) {
    env.unpair();
    env.assert_offline("没有登记过设备").await;
    let d = Device::new();
    assert_eq!(d.open(false, None).await.unwrap_err(), "relay_not_set");
    d.claim(env, &env.code()).await.unwrap();
    env.assert_offline("已登记，没有开放").await;
    d.open(false, None).await.unwrap();
    d.wait(TunnelState::Online, 15).await;
    assert_eq!(d.service.scope(), ExposureScope::Public);

    // 上面的探测请求本身带有假令牌，只看配对开始之后的流量
    let start = env.captured().await.len();
    let (mut bridge, token) = d.pair().await;
    let code = bridge.full_flow(&d).await;
    let seen = env.captured().await.split_off(start);
    assert!(seen.len() > 4000, "没有抓到流量");
    let plain_code = code.replace('-', "");
    let bare = token.as_str();
    for marker in [
        SECRET,
        USER,
        QUERY,
        REASON,
        PW,
        bare,
        code.as_str(),
        plain_code.as_str(),
        "Bearer",
        "x-auth-code",
        "X-Auth-Code",
        "password",
        "masked_account",
        "/v1/search",
        "/v1/pair",
        "item_ref",
    ] {
        assert!(!contains(&seen, marker), "桥接模式下抓到了 {marker}");
    }
    // 只开了桥接：直连与离线逐字相同，哪怕设备在线
    for (s, _, b) in env.probes().await.iter().take(7) {
        assert_eq!((*s, b.as_str()), (503, r#"{"error":"unavailable"}"#));
    }

    // 对照：直连模式跳板看得到，说明抓包方法有效，也说明文档里的提醒属实
    d.service.close();
    let local = d.client(Access::Local);
    let direct = d.client(Access::Direct);
    d.open(true, None).await.unwrap();
    d.wait(TunnelState::Online, 15).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    for wrong in [local.as_str(), token.as_str(), "00"] {
        let (s, b) = env.api(wrong, "GET", "/health", "").await;
        assert_eq!((s, b.as_str()), (401, r#"{"error":"unauthorized"}"#));
    }
    let (s, b) = env
        .api(
            &direct,
            "POST",
            "/v1/search",
            &json!({"query":QUERY}).to_string(),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let hit: Value = serde_json::from_str(&b).unwrap();
    let body =
        json!({"item_ref":hit["results"][0]["item_ref"],"fields":["password"],"reason":REASON});
    let (_, b) = env
        .api(&direct, "POST", "/v1/requests", &body.to_string())
        .await;
    let id = serde_json::from_str::<Value>(&b).unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let code = d.approve(&id);
    let bearer = format!("Bearer {direct}");
    let auth = [
        ("authorization", bearer.as_str()),
        ("x-auth-code", code.expose()),
    ];
    let path = format!("/v1/requests/{id}/secret");
    let in_url = format!("{path}?code={}", code.expose());
    assert_eq!(env.http("GET", &in_url, &auth[..1], "").await.0, 400);
    let mut origin = auth.to_vec();
    origin.push(("origin", "https://evil.example"));
    assert_eq!(env.http("GET", &path, &origin, "").await.0, 403);
    assert_eq!(env.http("HEAD", &path, &auth, "").await.0, 405);
    let (s, h, b) = env.http("GET", &path, &auth, "").await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(h["cache-control"], "no-store");
    assert!(b.contains(SECRET));
    let (s, _, b) = env.http("GET", &path, &auth, "").await;
    assert_eq!(s, 410);
    assert!(!b.contains(SECRET));
    // Streamable HTTP MCP 直连
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"f","version":"1"}}});
    let (s, b) = env.api(&direct, "POST", "/mcp", &init.to_string()).await;
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("suishen-vault"));
    let seen = env.captured().await;
    for marker in [SECRET, direct.as_str(), code.expose()] {
        assert!(contains(&seen, marker), "对照组应当抓得到");
    }
    // 主机名不对与离线同样答复
    let (s, _, b) = env
        .http("GET", "/health", &[("host", "other.example")], "")
        .await;
    if matches!(env.kind, Kind::Local { .. }) {
        assert_eq!((s, b.as_str()), (503, r#"{"error":"unavailable"}"#));
    }
    d.service.close();
}

/// 断网后自动重连；跳板重启后身份仍在。AC-REL-07
async fn scenario_reconnect(env: &Env) {
    let d = Device::online(env, false).await;
    let (mut bridge, _) = d.pair().await;
    let id = bridge.request().await;
    env.cut();
    d.wait(TunnelState::Offline, 40).await;
    assert_eq!(
        d.service.scope(),
        ExposureScope::Public,
        "断线不改变开放范围"
    );
    assert!(
        bridge
            .tool("get_request_status", json!({"request_id":id}))
            .await
            .is_err()
    );
    env.restore();
    d.wait(TunnelState::Online, 90).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    // 同一次开放内，断线不作废申请
    let code = d.approve(&id);
    let got = bridge
        .tool("get_secret", json!({"request_id":id,"code":code.expose()}))
        .await
        .unwrap();
    assert_eq!(got["fields"][0]["value"], SECRET);

    if let Kind::Docker { relay, .. } = &env.kind {
        docker(&["restart", "-t", "2", relay]);
        d.wait(TunnelState::Offline, 40).await;
        d.wait(TunnelState::Online, 90).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            bridge
                .tool("get_request_status", json!({"request_id":id}))
                .await
                .is_ok()
        );
    }
    d.service.close();
}

/// 新设备接管：旧设备立即断开且失效，重启后仍成立。AC-REL-02 AC-REL-03
async fn scenario_takeover(env: &Env) {
    let old = Device::online(env, false).await;
    let (mut bridge, _) = old.pair().await;
    let id = bridge.request().await;
    let new = Device::new();
    let code = env.code();
    let start = Instant::now();
    new.claim(env, &code).await.unwrap();
    old.wait(TunnelState::Superseded, 5).await;
    assert!(start.elapsed() < Duration::from_secs(6));
    assert_eq!(old.service.scope(), ExposureScope::Closed);
    assert!(old.with(|e| e.pending()).as_array().unwrap().is_empty());
    assert_eq!(old.with(|e| e.relay_info())["superseded"], true);
    assert_eq!(old.open(false, None).await.unwrap_err(), "relay_superseded");
    // 用过的配对码不能再用
    let again = Device::new();
    assert_eq!(again.claim(env, &code).await.unwrap_err(), "relay_code");
    assert_eq!(old.claim(env, &code).await.unwrap_err(), "relay_code");

    new.open(false, None).await.unwrap();
    new.wait(TunnelState::Online, 15).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // 旧设备的桥接固定的是旧公钥，连不上新设备
    assert!(
        bridge
            .tool("get_request_status", json!({"request_id":id}))
            .await
            .is_err()
    );
    if let Kind::Docker { relay, .. } = &env.kind {
        docker(&["restart", "-t", "2", relay]);
        new.wait(TunnelState::Offline, 40).await;
        new.wait(TunnelState::Online, 90).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (mut fresh, _) = new.pair().await;
    fresh.full_flow(&new).await;

    // 管理员重置后，当前设备也立即失效
    env.unpair();
    new.wait(TunnelState::Rejected, 20).await;
    env.assert_offline("重置之后").await;
    new.service.close();
}

/// 伪造设备。AC-REL-02 AC-REL-04
async fn scenario_forged_devices(env: &Env) {
    let d = Device::online(env, false).await;
    let (mut bridge, _) = d.pair().await;
    let e = env.endpoint();
    let connect = || async {
        dial::upgrade(&e, env.ca.as_deref(), DEVICE_PATH, DEVICE_PROTOCOL)
            .await
            .unwrap()
            .unwrap()
    };
    let stranger = Identity::generate().unwrap();
    for (host, code) in [
        (e.authority(), None),
        (e.authority(), Some(PairCode::generate().unwrap())),
        // 别的跳板骗来的签名在这里无效
        ("evil.example".into(), None),
    ] {
        let mut io = connect().await;
        let v = handshake::prove(&mut io, &host, &stranger, code.as_ref(), true)
            .await
            .unwrap();
        assert_eq!(v, Verdict::Rejected);
    }
    // 冒用当前设备的公钥，但没有私钥
    let mut io = connect().await;
    let len = io.read_u32().await.unwrap() as usize;
    let mut challenge = vec![0; len];
    io.read_exact(&mut challenge).await.unwrap();
    let forged = json!({"key": env.current_key(), "sig": hex::encode([2u8; 64]),
        "claim": null, "direct": true})
    .to_string();
    io.write_u32(forged.len() as u32).await.unwrap();
    io.write_all(forged.as_bytes()).await.unwrap();
    let len = io.read_u32().await.unwrap() as usize;
    let mut reply = vec![0; len];
    io.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, br#""rejected""#);
    // 垃圾数据
    let mut io = connect().await;
    io.write_all(&[255; 64]).await.unwrap();
    // 真设备不受影响
    assert_eq!(d.service.tunnel(), TunnelState::Online);
    bridge.full_flow(&d).await;
    d.service.close();

    // 跳板被攻破、放上一台假设备：桥接核对公钥不符，不会交出令牌
    let evil = Device::online(env, true).await;
    let before = env.captured().await.len();
    assert_eq!(
        bridge
            .tool("search_entries", json!({"query":QUERY}))
            .await
            .unwrap_err(),
        "unavailable"
    );
    let seen = env.captured().await;
    let token: Value = serde_json::from_slice(
        &std::fs::read(bridge.dir.path().join("codex-remote.json")).unwrap(),
    )
    .unwrap();
    assert!(!contains(&seen[before..], token["token"].as_str().unwrap()));
    evil.service.close();
}

/// 开关：关闭立即断开；切换作废一切；到期自动关闭。AC-NET-01 AC-NET-03 AC-NET-04
async fn scenario_switches(env: &Env) {
    let d = Device::online(env, true).await;
    let (mut bridge, _) = d.pair().await;
    let id = bridge.request().await;
    let code = d.approve(&id);
    let start = Instant::now();
    d.service.close();
    assert_eq!(d.service.scope(), ExposureScope::Closed);
    assert_eq!(d.service.tunnel(), TunnelState::Off);
    loop {
        let (s, _, b) = env.http("GET", "/health", &[], "").await;
        if (s, b.as_str()) == (503, r#"{"error":"unavailable"}"#) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(1), "关闭后仍可访问");
    }
    env.assert_offline("关闭之后").await;
    assert!(
        bridge
            .tool("get_secret", json!({"request_id":id,"code":code.expose()}))
            .await
            .is_err()
    );
    // 关闭后不再尝试连接
    if let Kind::Local { tap, .. } = &env.kind {
        use std::sync::atomic::Ordering::SeqCst;
        let before = tap.accepted.load(SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(tap.accepted.load(SeqCst), before, "关闭后仍在外连");
    }
    // 仅本机：不连跳板
    d.service
        .open_shared(d.engine.clone(), 0, None)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    env.assert_offline("仅本机").await;
    d.service.close();

    // 重新打开后旧申请、旧码无效
    d.open(false, Some(Duration::from_secs(12))).await.unwrap();
    let opened = Instant::now();
    d.wait(TunnelState::Online, 10).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        bridge
            .tool("get_secret", json!({"request_id":id,"code":code.expose()}))
            .await
            .unwrap_err(),
        "unknown_request"
    );
    // 到期自动关闭
    let left = Duration::from_secs(12).saturating_sub(opened.elapsed());
    tokio::time::sleep(left + Duration::from_millis(600)).await;
    assert_eq!(d.service.scope(), ExposureScope::Closed);
    assert_eq!(d.service.tunnel(), TunnelState::Off);
    env.assert_offline("到期之后").await;
    assert!(
        bridge
            .tool("search_entries", json!({"query":QUERY}))
            .await
            .is_err()
    );
}

/// 公网限流比本机严，且有效令牌不受他人失败影响。
async fn scenario_limits(env: &Env) {
    let d = Device::online(env, true).await;
    let direct = d.client(Access::Direct);
    let body = json!({"query":QUERY}).to_string();
    let mut got = Vec::new();
    for _ in 0..6 {
        got.push(env.api(&direct, "POST", "/v1/search", &body).await.0);
    }
    assert_eq!(got, [200, 200, 200, 200, 200, 429]);
    let mut bad = Vec::new();
    for _ in 0..12 {
        bad.push(env.api("00", "GET", "/health", "").await.0);
    }
    assert_eq!(bad[..10], [401; 10]);
    assert_eq!(bad[10..], [429; 2]);
    assert_eq!(env.api(&direct, "GET", "/health", "").await.0, 200);
    let big = " ".repeat(70_000);
    assert_eq!(env.api(&direct, "POST", "/v1/search", &big).await.0, 413);
    d.service.close();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_modes_and_capture() {
    scenario_both_modes_and_capture(&Env::local().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_after_network_loss() {
    scenario_reconnect(&Env::local().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn takeover_replaces_the_old_device() {
    scenario_takeover(&Env::local().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_devices_are_refused() {
    scenario_forged_devices(&Env::local().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn switches_take_effect_at_once() {
    scenario_switches(&Env::local().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_limits_are_stricter() {
    scenario_limits(&Env::local().await).await;
}

/// 跳板自身按来源限流，离线与在线时一致。
#[tokio::test]
async fn relay_limits_each_source() {
    let env = Env::local_with(3).await;
    let mut got = Vec::new();
    for _ in 0..5 {
        got.push(env.http("GET", "/", &[], "").await.0);
    }
    assert_eq!(got, [503, 503, 503, 429, 429]);
    // 换一个来源不受影响；伪造的前段地址不算数
    let h = [("x-forwarded-for", "192.0.2.1, 198.51.100.7")];
    assert_eq!(env.http("GET", "/", &h, "").await.0, 503);
}

/// 配对串只能用一次、会过期、错误密钥五次即废；没有配对时陌生公钥在握手阶段就被拒绝。AC-MCP-07
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_is_one_time_and_confirmed_on_the_device() {
    let env = Env::local().await;
    let d = Device::online(&env, false).await;
    let text = d
        .with(|e| e.pairing_begin("假桥接", vec![], Auth::Password(&PW.into())))
        .unwrap();
    assert!(
        d.with(|e| e.pairing_begin("x", vec![], Auth::Password(&"wrong-password-00".into())))
            .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let run = |text: String| {
        let mut c = bridge_command(&dir, &["pair", "claude"]);
        async move {
            let mut child = c
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(text.as_bytes()).await.unwrap();
            drop(stdin);
            child.wait_with_output().await.unwrap()
        }
    };
    // 改动配对密钥的最后一位
    let raw = hex::decode(text.expose().strip_prefix("svp1:").unwrap()).unwrap();
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["secret"] = json!("00".repeat(16));
    let wrong = format!("svp1:{}", hex::encode(v.to_string()));
    for _ in 0..5 {
        assert!(!run(wrong.clone()).await.status.success());
    }
    assert_eq!(d.with(|e| e.pairing_info()), Value::Null, "错五次即废");
    assert!(!run(text.expose().to_owned()).await.status.success());
    // 用户取消
    let text = d
        .with(|e| e.pairing_begin("假桥接", vec![], Auth::Password(&PW.into())))
        .unwrap();
    d.with(|e| e.pairing_cancel());
    assert!(!run(text.expose().to_owned()).await.status.success());
    assert!(d.with(|e| e.pairing_accept()).is_err());
    assert_eq!(d.with(|e| e.clients()), json!([]));
    // 吊销后桥接立即失效
    let (mut bridge, _) = d.pair().await;
    assert!(
        bridge
            .tool("search_entries", json!({"query":QUERY}))
            .await
            .is_ok()
    );
    let id = d.with(|e| e.clients())[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = vault_core::search::ClientId(hex::decode(id).unwrap().try_into().unwrap());
    d.with(|e| e.revoke_client(id)).unwrap();
    assert!(
        bridge
            .tool("search_entries", json!({"query":QUERY}))
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 Docker，用 npm run test:relay 运行"]
async fn docker_end_to_end() {
    let env = Env::docker();
    scenario_both_modes_and_capture(&env).await;
    scenario_limits(&env).await;
    scenario_forged_devices(&env).await;
    scenario_switches(&env).await;
    scenario_takeover(&env).await;
    scenario_reconnect(&env).await;
}

/// 由 scripts/test-deploy.mjs 运行：容器是按文档部署出来的。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 Docker，用 npm run test:deploy 运行"]
async fn docker_deployed_by_the_docs() {
    let env = Env::docker();
    scenario_takeover(&env).await;
    scenario_reconnect(&env).await;
}

/// 文档里的 ssh -R 替代方案：设备只开仅本机。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "需要 Docker，用 npm run test:deploy 运行"]
async fn docker_ssh_reverse() {
    let env = Env::docker();
    let Kind::Docker { relay, .. } = &env.kind else {
        unreachable!()
    };
    let d = Device::new();
    let port = d
        .service
        .open_shared(d.engine.clone(), 0, None)
        .await
        .unwrap();
    let token = d.client(Access::Local);
    // 文档里两端端口相同；测试用空闲端口
    let script = format!(
        "sed -i 's/47600/{port}/g' /etc/nginx/conf.d/vault-ssh.conf /home/tunnel/.ssh/authorized_keys \
         && nginx -t && systemctl reload nginx"
    );
    docker(&["exec", relay, "bash", "-ec", &script]);
    let args = std::env::var("SV_SSH_ARGS").unwrap();
    let args = args.replace("47600", &port.to_string());
    let mut ssh = Command::new("ssh")
        .args(args.split_whitespace())
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let start = Instant::now();
    while env.api(&token, "GET", "/health", "").await.0 != 200 {
        assert!(start.elapsed() < Duration::from_secs(20), "ssh -R 没有通");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let body = json!({"query":QUERY}).to_string();
    let (s, b) = env.api(&token, "POST", "/v1/search", &body).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(env.api("00", "GET", "/health", "").await.0, 401);
    // App 里全部关闭后，ssh 还连着也拿不到任何东西
    d.service.close();
    let start = Instant::now();
    loop {
        let (s, b) = env.api(&token, "GET", "/health", "").await;
        if s == 503 {
            assert_eq!(b, r#"{"error":"unavailable"}"#);
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    ssh.kill().await.unwrap();
}
