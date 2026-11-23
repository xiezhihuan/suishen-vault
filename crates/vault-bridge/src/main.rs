//! stdio 只传 MCP 消息。回环端口可配置，目标地址固定，禁用代理和重定向。
use reqwest::Client;
use rmcp::ServiceExt;
use serde_json::{Value, json};
use std::{
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};
use vault_core::SecretString;
use vault_service::{
    DEFAULT_PORT, ServiceError,
    mcp::{Backend, Operation, Tools},
};

#[derive(Clone)]
struct Device {
    http: Client,
    base: String,
    token: Arc<SecretString>,
}
const OFF: ServiceError = ServiceError(503, "unavailable");
impl Device {
    async fn send(&self, r: reqwest::RequestBuilder) -> Result<String, ServiceError> {
        let response = r
            .bearer_auth(self.token.expose())
            .send()
            .await
            .map_err(|_| OFF)?;
        let status = response.status();
        let data = response.text().await.map_err(|_| OFF)?;
        if status.is_success() {
            return Ok(data);
        }
        let value = serde_json::from_str::<Value>(&data).unwrap_or(Value::Null);
        let key = value["error"].as_str().unwrap_or_default();
        let known = [
            "unauthorized",
            "not_ready",
            "missing_code",
            "invalid_code",
            "gone",
            "unknown_request",
            "query_too_short",
            "rate_limited",
            "search_paused",
            "unknown_item",
            "invalid_fields",
            "invalid_reason",
            "too_many_pending",
            "cooldown",
            "invalid_params",
        ];
        Err(ServiceError(
            status.as_u16(),
            known
                .into_iter()
                .find(|s| *s == key)
                .unwrap_or("unavailable"),
        ))
    }
}
impl Backend for Device {
    async fn execute(&self, op: Operation) -> Result<String, ServiceError> {
        let root = &self.base;
        let req = match op {
            Operation::Search(q) => self
                .http
                .post(format!("{root}/v1/search"))
                .json(&json!({"query":q})),
            Operation::Request {
                item_ref,
                fields,
                reason,
            } => self
                .http
                .post(format!("{root}/v1/requests"))
                .json(&json!({ "item_ref":item_ref,"fields":fields,"reason":reason })),
            Operation::Status(id, wait) => {
                let start = Instant::now();
                loop {
                    let data = self
                        .send(self.http.get(format!("{root}/v1/requests/{id}")))
                        .await?;
                    if wait == 0
                        || start.elapsed() >= Duration::from_secs(wait.into())
                        || serde_json::from_str::<Value>(&data).map_err(|_| OFF)?["state"]
                            != "pending"
                    {
                        return Ok(data);
                    }
                    tokio::time::sleep(Duration::from_millis(750)).await;
                }
            }
            Operation::Secret(id, code) => self
                .http
                .get(format!("{root}/v1/requests/{id}/secret"))
                .header(
                    "X-Auth-Code",
                    reqwest::header::HeaderValue::from_str(&code)
                        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
                ),
        };
        self.send(req).await
    }
}
fn valid_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}
async fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [action, profile] = args.as_slice() else {
        return Err(());
    };
    if !matches!(profile.as_str(), "claude" | "codex") {
        return Err(());
    }
    let entry = keyring::Entry::new("dev.suishen.vault.bridge", profile).map_err(|_| ())?;
    if action == "store-token" {
        let token = SecretString::new(
            rpassword::prompt_password("粘贴 App 签发的客户端令牌（输入隐藏）：")
                .map_err(|_| ())?,
        );
        if !valid_token(token.expose()) {
            return Err(());
        }
        return entry.set_password(token.expose()).map_err(|_| ());
    }
    if action != "mcp" {
        return Err(());
    }
    let var = if profile == "claude" {
        "SUISHEN_CLAUDE_TOKEN"
    } else {
        "SUISHEN_CODEX_TOKEN"
    };
    let token = SecretString::new(
        std::env::var(var)
            .or_else(|_| entry.get_password())
            .map_err(|_| ())?,
    );
    if !valid_token(token.expose()) {
        return Err(());
    }
    let port = std::env::var("SUISHEN_PORT")
        .ok()
        .map(|p| p.parse::<u16>())
        .transpose()
        .map_err(|_| ())?
        .unwrap_or(DEFAULT_PORT);
    let api = Device {
        base: format!("http://127.0.0.1:{port}"),
        http: Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| ())?,
        token: Arc::new(token),
    };
    Tools(api)
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|_| ())?
        .waiting()
        .await
        .map_err(|_| ())?;
    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}
