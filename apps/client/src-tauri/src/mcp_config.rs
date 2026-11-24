//! 生成可复制的 AI 客户端配置，不读取也不包含令牌。
use crate::error::{Ui, UiError, fail};
use serde_json::{Value, json};
use vault_service::DEFAULT_PORT;

fn bridge_path() -> String {
    let name = if cfg!(windows) {
        "vault-bridge.exe"
    } else {
        "vault-bridge"
    };
    // 安装包把桥接程序放在主程序旁边；开发构建也在同一目录。
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.is_file())
        .map_or_else(|| name.to_owned(), |p| p.to_string_lossy().into_owned())
}

fn quote(s: &str) -> String {
    Value::from(s).to_string()
}

/// `relay` 为已配对跳板的地址，公网两种方式需要。
pub fn build(client: &str, transport: &str, port: u16, relay: Option<&str>) -> Ui<Value> {
    let local = match transport {
        "stdio" | "http" => transport,
        // 公网：桥接端到端加密，或直连 HTTPS
        "bridge" => "stdio",
        "direct" => "http",
        _ => return Err(UiError::internal()),
    };
    let remote = local != transport;
    let url = match (remote, relay) {
        (false, _) => format!("http://127.0.0.1:{port}/mcp"),
        (true, Some(r)) => format!("{r}/mcp"),
        (true, None) => return fail("relay_not_set", "还没有配对跳板，请先到「开放范围」配对"),
    };
    let args = if remote {
        json!(["mcp", client, "remote"])
    } else {
        json!(["mcp", client])
    };
    if !matches!(client, "claude" | "codex") {
        return Err(UiError::internal());
    }
    let command = bridge_path();
    let custom_port = !remote && port != DEFAULT_PORT;
    let text = match (client, local) {
        ("claude", "stdio") => {
            let mut server = json!({"type":"stdio","command":command,"args":args});
            if custom_port {
                server["env"] = json!({"SUISHEN_PORT": port.to_string()});
            }
            pretty(server)
        }
        ("claude", _) => pretty(json!({"type":"http","url":url,
            "headers":{"Authorization":"Bearer ${SUISHEN_CLAUDE_TOKEN}"}})),
        (_, "stdio") => {
            let mut t = format!(
                "[mcp_servers.suishen-vault]\ncommand = {}\nargs = {args}",
                quote(&command)
            );
            if custom_port {
                t.push_str(&format!("\nenv = {{ SUISHEN_PORT = \"{port}\" }}"));
            }
            t
        }
        _ => format!(
            "[mcp_servers.suishen-vault]\nurl = {}\nbearer_token_env_var = \"SUISHEN_CODEX_TOKEN\"",
            quote(&url)
        ),
    };
    let file = if client == "claude" {
        ".mcp.json"
    } else {
        ".codex/config.toml"
    };
    let action = if remote { "pair" } else { "store-token" };
    let store = (local == "stdio").then(|| format!("\"{command}\" {action} {client}"));
    let env = (local == "http").then(|| format!("SUISHEN_{}_TOKEN", client.to_uppercase()));
    Ok(json!({"file": file, "text": text, "store_command": store, "env": env}))
}

fn pretty(server: Value) -> String {
    serde_json::to_string_pretty(&json!({"mcpServers":{"suishen-vault":server}}))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_cover_both_clients_and_never_carry_tokens() {
        for client in ["claude", "codex"] {
            for transport in ["stdio", "http"] {
                let v = build(client, transport, 50000, None).unwrap();
                let text = v["text"].as_str().unwrap();
                assert!(text.contains("50000"), "{client} {transport}");
                assert!(text.contains("suishen-vault"));
                assert_eq!(v["store_command"].is_null(), transport == "http");
            }
        }
        assert!(
            !build("claude", "stdio", DEFAULT_PORT, None).unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("SUISHEN_PORT")
        );
        assert!(build("x", "stdio", 1, None).is_err());
    }

    #[test]
    fn public_configs_point_at_the_relay() {
        let relay = Some("https://relay.example.com");
        for client in ["claude", "codex"] {
            assert!(build(client, "bridge", 50000, None).is_err());
            let v = build(client, "bridge", 50000, relay).unwrap();
            let text = v["text"].as_str().unwrap();
            assert!(text.contains("remote") && !text.contains("50000"));
            assert!(v["store_command"].as_str().unwrap().contains(" pair "));
            let v = build(client, "direct", 50000, relay).unwrap();
            let text = v["text"].as_str().unwrap();
            assert!(text.contains("https://relay.example.com/mcp"));
            assert!(!text.contains("127.0.0.1") && v["store_command"].is_null());
        }
    }
}
