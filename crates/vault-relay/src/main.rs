//! 用法见 docs/公网跳板.md。
use std::{io::Write, path::PathBuf, process::ExitCode};
use vault_relay::{CODE_TTL, Config, State, bind};
use vault_tunnel::Endpoint;

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn say(text: &str) {
    let _ = writeln!(std::io::stdout(), "{text}");
}

fn fail(text: &str) -> ExitCode {
    let _ = writeln!(std::io::stderr(), "vault-relay: {text}");
    ExitCode::FAILURE
}

const USAGE: &str = "用法：vault-relay serve | pair-code | status | unpair
环境变量：
  VAULT_RELAY_HOST        对外主机名，非 443 端口要带端口（serve 必填）
  VAULT_RELAY_LISTEN      监听地址，默认 127.0.0.1:7470
  VAULT_RELAY_STATE       状态目录，默认 /var/lib/vault-relay
  VAULT_RELAY_PER_SOURCE  每来源每分钟请求数，默认 60";

fn main() -> ExitCode {
    // panic 正文可能带值，一律丢弃
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<_> = std::env::args().skip(1).collect();
    let state = State::new(PathBuf::from(env(
        "VAULT_RELAY_STATE",
        "/var/lib/vault-relay",
    )));
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["serve"] => serve(state),
        ["pair-code"] => match state.issue_code() {
            Ok(code) => {
                say(&format!(
                    "配对码：{}\n{} 分钟内有效，只能用一次。在新设备的 App 里输入后，当前设备立即失效。",
                    &*code.display(),
                    CODE_TTL.as_secs() / 60
                ));
                ExitCode::SUCCESS
            }
            Err(_) => fail("不能写入状态目录，请检查 VAULT_RELAY_STATE 与权限"),
        },
        ["status"] => {
            say(if state.current().is_some() {
                "已登记一台设备"
            } else {
                "还没有登记设备"
            });
            ExitCode::SUCCESS
        }
        ["unpair"] => match state.unpair() {
            Ok(()) => {
                say("已清除登记，当前设备立即失效。");
                ExitCode::SUCCESS
            }
            Err(_) => fail("不能写入状态目录，请检查 VAULT_RELAY_STATE 与权限"),
        },
        _ => {
            say(USAGE);
            ExitCode::from(2)
        }
    }
}

fn serve(state: State) -> ExitCode {
    let Ok(host) = Endpoint::parse(&env("VAULT_RELAY_HOST", "")) else {
        return fail("VAULT_RELAY_HOST 未设置或格式不对，例如 relay.example.com");
    };
    let Ok(listen) = env("VAULT_RELAY_LISTEN", "127.0.0.1:7470").parse() else {
        return fail("VAULT_RELAY_LISTEN 格式不对，例如 127.0.0.1:7470");
    };
    let mut config = Config::new(host.authority(), state);
    match env("VAULT_RELAY_PER_SOURCE", "60").parse() {
        Ok(n @ 1..=100_000) => {
            config.per_source = n;
            config.total = n.saturating_mul(5);
        }
        _ => return fail("VAULT_RELAY_PER_SOURCE 须为 1 到 100000"),
    }
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        return fail("无法启动");
    };
    runtime.block_on(async {
        match bind(listen, config).await {
            Ok((_, run)) => {
                tokio::select! {
                    _ = run => {}
                    _ = stop() => {}
                }
                ExitCode::SUCCESS
            }
            Err(_) => fail("无法监听，端口可能被占用"),
        }
    })
}

/// 容器里是 1 号进程，须自己处理终止信号。
async fn stop() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
