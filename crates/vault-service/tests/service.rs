use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};
use vault_core::{
    Auth, Clock, SecretString, Setup, Vault,
    model::{AiField, ItemDraft, ItemKind},
    search::ClientId,
};
use vault_service::{Engine, LocalApproval, ServiceHandle};

const PW: &str = "fake-master-鲸鱼-0001";
const SECRET: &str = "Fake-Violet-Secret-7172";
const USER: &str = "fake-oriole-account-1891";
const QUERY: &str = "Cassiopeia";
struct TestClock(AtomicI64);
impl Clock for TestClock {
    fn wall_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
    fn mono_ms(&self) -> u64 {
        0
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    clock: Arc<TestClock>,
    service: ServiceHandle,
    http: Client,
    base: String,
    port: u16,
    a: ClientId,
    b: ClientId,
    token: SecretString,
    other: SecretString,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(TestClock(AtomicI64::new(1800000000000)));
        let setup = Setup::begin(&PW.into()).unwrap();
        let key = setup.recovery_key();
        let answers = setup
            .challenge()
            .map(|i| key.expose().split('-').nth(i as usize).unwrap());
        let mut v = setup
            .confirm(&dir.path().join("test.svault"), answers, clock.clone())
            .unwrap();
        for (name, tag, hidden) in [
            (QUERY, "工作", false),
            ("Mintleaf", "工作", false),
            ("Amaryllis", "私人", false),
            ("Hydrangea", "工作", true),
        ] {
            let mut item = ItemDraft::new(ItemKind::Login, name);
            item.secrets.username = Some(USER.into());
            item.secrets.password = Some(SECRET.into());
            item.tags = vec![tag.into()];
            item.ai_hidden = hidden;
            v.add(&item).unwrap();
        }
        let mut engine = Engine::new(v, clock.clone()).unwrap();
        let (a, token) = engine
            .add_client("假客户端甲", vec!["工作".into()])
            .unwrap();
        let (b, other) = engine.add_client("假客户端乙", vec![]).unwrap();
        let service = ServiceHandle::new();
        let port = service.open_loopback(engine, 0, None).await.unwrap();
        Self {
            dir,
            clock,
            service,
            http: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(6))
                .build()
                .unwrap(),
            base: format!("http://127.0.0.1:{port}"),
            port,
            a,
            b,
            token,
            other,
        }
    }
    async fn search(&self, query: &str) -> Value {
        self.http
            .post(format!("{}/v1/search", self.base))
            .bearer_auth(self.token.expose())
            .json(&json!({"query":query}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
    async fn grant(&self, q: &str, fields: &[&str]) -> String {
        let hit = self.search(q).await;
        let r:Value=self.http.post(format!("{}/v1/requests",self.base)).bearer_auth(self.token.expose()).json(&json!({"item_ref":hit["results"][0]["item_ref"],"fields":fields,"reason":"假用途：填写测试表单"})).send().await.unwrap().json().await.unwrap();
        r["request_id"].as_str().expect("应签发申请句柄").into()
    }
    fn issue(&self, id: &str, f: AiField) -> SecretString {
        self.service
            .local(|e| e.approve(id, vec![f], Auth::Password(&PW.into()), true))
            .map(|v| match v {
                LocalApproval::Code(c) => c,
                _ => panic!("应出码"),
            })
            .unwrap()
    }
    fn get(&self, id: &str) -> RequestBuilder {
        self.http
            .get(format!("{}/v1/requests/{id}/secret", self.base))
            .bearer_auth(self.token.expose())
    }
    async fn failure(&self, r: RequestBuilder, status: u16) -> Value {
        let res = r.send().await.unwrap();
        assert_eq!(res.status().as_u16(), status);
        assert_eq!(res.headers()["cache-control"], "no-store");
        assert_eq!(res.headers()["x-content-type-options"], "nosniff");
        assert!(!res.headers().contains_key("access-control-allow-origin"));
        let text = res.text().await.unwrap();
        for marker in [PW, SECRET, USER, self.token.expose(), self.other.expose()] {
            assert!(!text.contains(marker), "错误响应泄露");
        }
        serde_json::from_str(&text).unwrap()
    }
    fn advance(&self, ms: i64) {
        self.clock.0.fetch_add(ms, Ordering::SeqCst);
    }
}
#[tokio::test]
async fn locked_service_isolates_clients_items_fields_and_consumes_atomically() {
    let f = Fixture::new().await;
    let a = f.grant(QUERY, &["password", "username"]).await;
    let b = f.grant("Mintleaf", &["username"]).await;
    f.failure(f.get(&a), 409).await;
    let wrong = SecretString::from("fake-wrong-master-000");
    assert!(
        f.service
            .local(|e| e.approve(&a, vec![AiField::Password], Auth::Password(&wrong), true))
            .is_err()
    );
    assert!(
        f.service
            .local(|e| e.approve(
                &b,
                vec![AiField::Password],
                Auth::Password(&PW.into()),
                true
            ))
            .is_err()
    );
    let code = f.issue(&a, AiField::Password);
    let other = f.issue(&b, AiField::Username);
    f.failure(f.get(&a), 400).await;
    f.failure(f.get(&a).header("x-auth-code", other.expose()), 403)
        .await;
    f.failure(f.get(&b).header("x-auth-code", code.expose()), 403)
        .await;
    f.failure(
        f.http
            .get(format!("{}/v1/requests/{a}/secret", f.base))
            .bearer_auth(f.other.expose())
            .header("x-auth-code", code.expose()),
        404,
    )
    .await;
    f.failure(
        f.http
            .get(format!("{}/v1/requests/{a}/secret", f.base))
            .header("x-auth-code", code.expose()),
        401,
    )
    .await;
    f.failure(
        f.http
            .get(format!(
                "{}/v1/requests/{a}/secret?code={}",
                f.base,
                code.expose()
            ))
            .bearer_auth(f.token.expose()),
        400,
    )
    .await;
    let req = || f.get(&a).header("x-auth-code", code.expose()).send();
    let (first, second) = tokio::join!(req(), req());
    let mut successes = 0;
    for response in [first.unwrap(), second.unwrap()] {
        if response.status() == 200 {
            successes += 1;
            let text = response.text().await.unwrap();
            assert!(!text.contains(USER));
            let v: Value = serde_json::from_str(&text).unwrap();
            assert!(v["fields"] == json!([{"name":"password","value":SECRET}]));
        } else {
            assert_eq!(response.status(), 410);
            assert!(!response.text().await.unwrap().contains(SECRET))
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(
        f.failure(f.get(&a).header("x-auth-code", code.expose()), 410)
            .await["state"],
        "redeemed"
    );
    let mut markers = vec![
        PW,
        SECRET,
        USER,
        QUERY,
        code.expose(),
        other.expose(),
        f.token.expose(),
        f.other.expose(),
    ];
    markers.push("假用途：填写测试表单");
    f.service.close();
    let mut v = Vault::open(&f.dir.path().join("test.svault")).unwrap();
    v.unlock(Auth::Password(&PW.into())).unwrap();
    let audit = v.recent_service_audit().unwrap();
    assert!(audit.len() >= 9);
    let mut decrypted = Vec::new();
    for row in audit {
        decrypted.extend_from_slice(&row)
    }
    for bytes in [decrypted, std::fs::read(v.path()).unwrap()] {
        for m in &markers {
            assert!(
                !bytes.windows(m.len()).any(|b| b == m.as_bytes()),
                "扫描发现敏感标记"
            );
        }
    }
}
#[tokio::test]
async fn timeout_five_failures_and_local_view() {
    let f = Fixture::new().await;
    let a = f.grant(QUERY, &["password"]).await;
    let code = f.issue(&a, AiField::Password);
    f.advance(120000);
    assert_eq!(
        f.failure(f.get(&a).header("x-auth-code", code.expose()), 410)
            .await["state"],
        "code_expired"
    );
    let a = f.grant(QUERY, &["password"]).await;
    let code = f.issue(&a, AiField::Password);
    for _ in 0..5 {
        f.failure(f.get(&a).header("x-auth-code", "malformed"), 403)
            .await;
    }
    assert_eq!(
        f.failure(f.get(&a).header("x-auth-code", code.expose()), 410)
            .await["state"],
        "locked"
    );
    let a = f.grant(QUERY, &["password"]).await;
    let v = f
        .service
        .local(|e| {
            e.approve(
                &a,
                vec![AiField::Password],
                Auth::Password(&PW.into()),
                false,
            )
        })
        .unwrap();
    assert!(
        matches!(v,LocalApproval::View(data) if std::str::from_utf8(&data).unwrap().contains(SECRET))
    );
    assert_eq!(f.failure(f.get(&a), 410).await["state"], "view_only");
    let a = f.grant(QUERY, &["password"]).await;
    f.advance(600000);
    assert_eq!(f.failure(f.get(&a), 410).await["state"], "expired");
}
#[tokio::test]
async fn host_origin_bounds_scopes_and_revocation() {
    let f = Fixture::new().await;
    let health = || {
        f.http
            .get(format!("{}/health", f.base))
            .bearer_auth(f.token.expose())
    };
    f.failure(health().header("host", "foreign.invalid"), 421)
        .await;
    f.failure(health().header("origin", "null"), 403).await;
    f.failure(
        f.http
            .post(format!("{}/v1/search", f.base))
            .bearer_auth(f.token.expose())
            .body(vec![b' '; 65537]),
        413,
    )
    .await;
    let search = f.search("Amaryllis").await;
    assert_eq!(search["results"], json!([]));
    assert_eq!(f.search("Hydrangea").await["results"], json!([]));
    assert_eq!(f.search("x").await["error"], "query_too_short");
    let a = f.grant(QUERY, &["password"]).await;
    let code = f.issue(&a, AiField::Password);
    f.service.local(|e| e.revoke_client(f.a)).unwrap();
    f.failure(f.get(&a).header("x-auth-code", code.expose()), 401)
        .await;
    f.service.close();
    let mut v = Vault::open_with_clock(&f.dir.path().join("test.svault"), f.clock.clone()).unwrap();
    assert!(v.ai().is_err());
    v.unlock(Auth::Password(&PW.into())).unwrap();
    let e = Engine::new(v, f.clock.clone()).unwrap();
    let port = f
        .service
        .open_loopback(e, 0, Some(Duration::from_millis(250)))
        .await
        .unwrap();
    let health = || f.http.get(format!("http://127.0.0.1:{port}/health"));
    f.failure(health().bearer_auth(f.token.expose()), 401).await;
    assert_eq!(
        health()
            .bearer_auth(f.other.expose())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(health().send().await.is_err());
}
#[tokio::test]
async fn pending_cap_denial_cooldown_and_search_quota() {
    let f = Fixture::new().await;
    let r = f.search(QUERY).await;
    let item = r["results"][0]["item_ref"].as_str().unwrap();
    let request = || {
        f.service
            .local(|e| e.request(f.a, item, vec![AiField::Password], "测试"))
    };
    assert!(
        f.service
            .local(|e| e.request(f.b, item, vec![AiField::Password], "测试"))
            .is_err()
    );
    let first = request().unwrap();
    request().unwrap();
    request().unwrap();
    assert_eq!(request().unwrap_err().1, "rate_limited");
    f.advance(60001);
    assert_eq!(request().unwrap_err().1, "too_many_pending");
    f.service
        .local(|e| e.deny(first["request_id"].as_str().unwrap()))
        .unwrap();
    assert_eq!(request().unwrap_err().1, "cooldown");
    for _ in 0..10 {
        assert!(f.search(QUERY).await["results"].is_array())
    }
    assert_eq!(f.search(QUERY).await["error"], "rate_limited");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "需安装官方 Python MCP SDK，并先构建 vault-bridge，见 docs/本机服务.md"]
async fn official_mcp_clients() {
    use std::{
        io::{BufRead, BufReader, Write},
        process::{Command, Stdio},
    };
    let f = Fixture::new().await;
    for (mode, token) in [("http", &f.token), ("stdio", &f.other)] {
        let mut child = Command::new("python3")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/sdk_client.py"))
            .arg(mode)
            .arg(f.port.to_string())
            .arg(std::env::var("SV_TEST_BRIDGE").unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{}", token.expose()).unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert!(
            vault_service::mcp::valid_id(line.trim()),
            "SDK 未能提交申请"
        );
        let code = f.issue(line.trim(), AiField::Password);
        writeln!(input, "{}", code.expose()).unwrap();
        drop(input);
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "SDK 流程失败");
        for marker in [PW, SECRET, USER, token.expose(), code.expose()] {
            assert!(
                !out.stderr
                    .windows(marker.len())
                    .any(|b| b == marker.as_bytes()),
                "SDK 日志含敏感内容"
            );
        }
    }
}

#[tokio::test]
async fn stateless_discovery_guards_and_safe_http_methods() {
    let f = Fixture::new().await;
    let version = "2026-07-28";
    let meta = json!({"io.modelcontextprotocol/protocolVersion":version,"io.modelcontextprotocol/clientInfo":{"name":"sdk-test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}});
    let message =
        |method: &str| json!({"jsonrpc":"2.0","id":4,"method":method,"params":{"_meta":meta}});
    let send = |method: &str, v: &str, body: Value| {
        f.http
            .post(format!("{}/mcp", f.base))
            .bearer_auth(f.token.expose())
            .header("MCP-Protocol-Version", v)
            .header("Mcp-Method", method)
            .header("accept", "application/json, text/event-stream")
            .json(&body)
    };
    let discover = send("server/discover", version, message("server/discover"))
        .send()
        .await
        .unwrap();
    assert_eq!(discover.status(), 200);
    assert!(!discover.headers().contains_key("mcp-session-id"));
    let info: Value = discover.json().await.unwrap();
    assert!(info["result"]["capabilities"]["tools"].is_object());
    let err = f
        .failure(send("tools/call", version, message("tools/list")), 400)
        .await;
    assert_eq!(err["error"]["code"], -32020);
    let invalid = f
        .failure(send("tools/list", "2099-01-01", message("tools/list")), 400)
        .await;
    assert!(invalid["error"]["code"].is_number());
    let id = f.grant(QUERY, &["password"]).await;
    let code = f.issue(&id, AiField::Password);
    let url = format!("{}/v1/requests/{id}/secret", f.base);
    for method in [
        reqwest::Method::HEAD,
        reqwest::Method::OPTIONS,
        reqwest::Method::POST,
    ] {
        let res = f
            .http
            .request(method, &url)
            .bearer_auth(f.token.expose())
            .header("x-auth-code", code.expose())
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 405);
    }
    f.failure(
        f.get(&id)
            .header("x-auth-code", code.expose())
            .header("sec-purpose", "prefetch"),
        400,
    )
    .await;
    assert_eq!(
        f.get(&id)
            .header("x-auth-code", code.expose())
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}
