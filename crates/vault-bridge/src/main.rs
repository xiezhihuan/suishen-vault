//! stdio 只传 MCP 消息。本机模式目标地址固定为回环；公网模式经跳板做端到端加密。
//! 两种模式都禁用代理和重定向。
mod remote;
mod store;

use remote::{Profile, Remote, Reply};
use reqwest::Client;
use rmcp::ServiceExt;
use serde_json::{Value, json};
use std::{
    io::{IsTerminal, Read, Write},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};
use store::Store;
use vault_core::SecretString;
use vault_service::{
    DEFAULT_PORT, ServiceError,
    mcp::{Backend, Operation, Tools},
};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Device {
    link: Arc<Link>,
    token: Arc<SecretString>,
}
enum Link {
    Local { http: Client, base: String },
    Remote(Remote),
}
const OFF: ServiceError = ServiceError(503, "unavailable");

/// 非法内容变成空值，让设备按错码计一次。
fn code_header(code: &str) -> reqwest::header::HeaderValue {
    let mut v = reqwest::header::HeaderValue::from_str(code)
        .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
    v.set_sensitive(true);
    v
}

impl Device {
    async fn send(
        &self,
        method: &'static str,
        path: &str,
        code: Option<&str>,
        body: Option<Value>,
    ) -> Result<String, ServiceError> {
        let reply = match &*self.link {
            Link::Local { http, base } => {
                let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| OFF)?;
                let mut r = http
                    .request(method, format!("{base}{path}"))
                    .bearer_auth(self.token.expose());
                if let Some(c) = code {
                    r = r.header("X-Auth-Code", code_header(c));
                }
                if let Some(b) = body {
                    r = r.json(&b);
                }
                let r = r.send().await.map_err(|_| OFF)?;
                Reply {
                    status: r.status().as_u16(),
                    body: r.text().await.map_err(|_| OFF)?,
                }
            }
            Link::Remote(r) => {
                let body = body.map_or_else(Vec::new, |b| b.to_string().into_bytes());
                r.call(method, path, Some(&self.token), code, body).await?
            }
        };
        if (200..300).contains(&reply.status) {
            return Ok(reply.body);
        }
        let value = serde_json::from_str::<Value>(&reply.body).unwrap_or(Value::Null);
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
            reply.status,
            known
                .into_iter()
                .find(|s| *s == key)
                .unwrap_or("unavailable"),
        ))
    }
    /// 公网每次查询都要重新握手，且限流更严，所以查得更稀。
    fn poll_interval(&self) -> Duration {
        match &*self.link {
            Link::Local { .. } => Duration::from_millis(750),
            Link::Remote(_) => Duration::from_secs(4),
        }
    }
}
impl Backend for Device {
    async fn execute(&self, op: Operation) -> Result<String, ServiceError> {
        match op {
            Operation::Search(q) => {
                self.send("POST", "/v1/search", None, Some(json!({"query":q})))
                    .await
            }
            Operation::Request {
                item_ref,
                fields,
                reason,
            } => {
                let body = json!({ "item_ref":item_ref,"fields":fields,"reason":reason });
                self.send("POST", "/v1/requests", None, Some(body)).await
            }
            Operation::Status(id, wait) => {
                let start = Instant::now();
                let path = format!("/v1/requests/{id}");
                loop {
                    let data = self.send("GET", &path, None, None).await?;
                    if wait == 0
                        || start.elapsed() + self.poll_interval() > Duration::from_secs(wait.into())
                        || serde_json::from_str::<Value>(&data).map_err(|_| OFF)?["state"]
                            != "pending"
                    {
                        return Ok(data);
                    }
                    tokio::time::sleep(self.poll_interval()).await;
                }
            }
            Operation::Secret(id, code) => {
                let path = format!("/v1/requests/{id}/secret");
                self.send("GET", &path, Some(&code), None).await
            }
        }
    }
}
fn valid_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 终端里隐藏输入；管道输入时整段读取。机密不从命令行参数来。
fn ask(prompt: &str) -> Result<SecretString, ()> {
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt)
            .map(SecretString::new)
            .map_err(|_| ());
    }
    let mut s = Zeroizing::new(String::new());
    std::io::stdin()
        .take(16 * 1024)
        .read_to_string(&mut s)
        .map_err(|_| ())?;
    Ok(SecretString::new(s.trim().to_owned()))
}

fn say(text: &str) {
    let _ = writeln!(std::io::stderr(), "{text}");
}

fn profile_store(profile: &str) -> Store {
    Store::new(&format!("{profile}-remote"))
}

async fn pair(profile: &str) -> Result<(), ()> {
    let text = ask("粘贴 App 显示的配对串（输入隐藏）：")?;
    let p = remote::pair(text.expose(), |f| {
        say(&format!(
            "指纹：{f}\n请在 App 上核对指纹一致后再确认。正在等待……"
        ));
    })
    .await
    .map_err(|()| say("配对没有完成。请确认 App 已开放公网，并重新生成配对串。"))?;
    let data = Zeroizing::new(serde_json::to_vec(&p).map_err(|_| ())?);
    profile_store(profile)
        .save(&data)
        .map_err(|()| say("凭据没有保存成功。请在 App 吊销这个客户端后重新配对。"))?;
    say("已配对，凭据已保存。");
    Ok(())
}

async fn serve(link: Link, token: SecretString) -> Result<(), ()> {
    if !valid_token(token.expose()) {
        return Err(());
    }
    Tools(Device {
        link: Arc::new(link),
        token: Arc::new(token),
    })
    .serve(rmcp::transport::stdio())
    .await
    .map_err(|_| ())?
    .waiting()
    .await
    .map_err(|_| ())?;
    Ok(())
}

fn local(profile: &str) -> Result<(Link, SecretString), ()> {
    let var = if profile == "claude" {
        "SUISHEN_CLAUDE_TOKEN"
    } else {
        "SUISHEN_CODEX_TOKEN"
    };
    let token = SecretString::new(
        std::env::var(var)
            .or_else(|_| keyring_entry(profile).and_then(|e| e.get_password()))
            .map_err(|_| ())?,
    );
    let port = std::env::var("SUISHEN_PORT")
        .ok()
        .map(|p| p.parse::<u16>())
        .transpose()
        .map_err(|_| ())?
        .unwrap_or(DEFAULT_PORT);
    let http = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| ())?;
    let base = format!("http://127.0.0.1:{port}");
    Ok((Link::Local { http, base }, token))
}

fn keyring_entry(profile: &str) -> keyring::Result<keyring::Entry> {
    keyring::Entry::new("dev.suishen.vault.bridge", profile)
}

fn store_token(profile: &str) -> Result<(), ()> {
    let token = SecretString::new(
        rpassword::prompt_password("粘贴 App 签发的客户端令牌（输入隐藏）：").map_err(|_| ())?,
    );
    if !valid_token(token.expose()) {
        return Err(());
    }
    keyring_entry(profile)
        .and_then(|e| e.set_password(token.expose()))
        .map_err(|_| ())
}

const USAGE: &str = "用法：vault-bridge <动作> <claude|codex>
  store-token <claude|codex>   保存本机令牌
  mcp <claude|codex>           本机 MCP
  pair <claude|codex>          与主设备做公网配对
  mcp <claude|codex> remote    公网 MCP（端到端加密）";

async fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let args: Vec<_> = args.iter().map(String::as_str).collect();
    match args[..] {
        ["store-token", p @ ("claude" | "codex")] => store_token(p),
        ["pair", p @ ("claude" | "codex")] => pair(p).await,
        ["mcp", p @ ("claude" | "codex")] => {
            let (link, token) = local(p)?;
            serve(link, token).await
        }
        ["mcp", p @ ("claude" | "codex"), "remote"] => {
            let data = profile_store(p).load()?;
            let p: Profile = serde_json::from_slice(&data).map_err(|_| ())?;
            serve(
                Link::Remote(Remote::open(&p)?),
                SecretString::new(p.token.clone()),
            )
            .await
        }
        _ => {
            say(USAGE);
            Err(())
        }
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {}));
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => ExitCode::FAILURE,
    }
}
