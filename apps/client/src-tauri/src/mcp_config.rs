//! 生成可复制的 AI 客户端配置，不读取也不包含令牌。
use crate::error::{Ui, UiError};
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

pub fn build(client: &str, transport: &str, port: u16) -> Ui<Value> {
    if !matches!(client, "claude" | "codex") || !matches!(transport, "stdio" | "http") {
        return Err(UiError::internal());
    }
    let command = bridge_path();
    let url = format!("http://127.0.0.1:{port}/mcp");
    let custom_port = port != DEFAULT_PORT;
    let text = match (client, transport) {
        ("claude", "stdio") => {
            let mut server = json!({"type":"stdio","command":command,"args":["mcp","claude"]});
            if custom_port {
                server["env"] = json!({"SUISHEN_PORT": port.to_string()});
            }
            pretty(server)
        }
        ("claude", _) => pretty(json!({"type":"http","url":url,
            "headers":{"Authorization":"Bearer ${SUISHEN_CLAUDE_TOKEN}"}})),
        (_, "stdio") => {
            let mut t = format!(
                "[mcp_servers.suishen-vault]\ncommand = {}\nargs = [\"mcp\", \"codex\"]",
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
    let store = (transport == "stdio").then(|| format!("\"{command}\" store-token {client}"));
    let env = (transport == "http").then(|| format!("SUISHEN_{}_TOKEN", client.to_uppercase()));
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
                let v = build(client, transport, 50000).unwrap();
                let text = v["text"].as_str().unwrap();
                assert!(text.contains("50000"), "{client} {transport}");
                assert!(text.contains("suishen-vault"));
                assert_eq!(v["store_command"].is_null(), transport == "http");
            }
        }
        assert!(
            !build("claude", "stdio", DEFAULT_PORT).unwrap()["text"]
                .as_str()
                .unwrap()
                .contains("SUISHEN_PORT")
        );
        assert!(build("x", "stdio", 1).is_err());
    }
}
