//! 写入过程中反复强杀进程，再打开检查。
mod common;
use common::*;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use vault_core::*;

const ENV: &str = "SVAULT_KILL_CHILD";

/// 子进程：不停写入，每提交一次就在标准输出报一行。平时直接返回。
#[test]
fn child_writer() {
    let Ok(path) = std::env::var(ENV) else { return };
    let mut v = Vault::open_with_clock(
        std::path::Path::new(&path),
        Arc::new(SystemClock::default()),
    )
    .ok()
    .unwrap();
    v.unlock(Auth::Password(&PW.into())).unwrap();
    let mut out = std::io::stdout().lock();
    let mut last = None;
    for i in 0.. {
        let body = format!("假正文-{i}-").repeat(300);
        let id = v.add(&note(&format!("条目{i}"), &body)).unwrap();
        writeln!(out, "added").unwrap();
        out.flush().unwrap();
        if let Some(prev) = last.replace(id) {
            v.update(prev, &note("已改", &body)).unwrap();
        }
    }
}

#[test]
fn killing_the_writer_never_corrupts_the_vault() {
    let (e, v) = new_env();
    drop(v);
    let mut committed = 0;
    for round in 0..8u64 {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_writer", "--nocapture", "--test-threads=1"])
            .env(ENV, e.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        // 等到第一次提交，再在不同时刻强杀
        let mut acked = 0;
        for l in lines.by_ref() {
            if l.unwrap().contains("added") {
                acked += 1;
                if acked > round {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_micros(700 * round * round));
        child.kill().unwrap();
        child.wait().unwrap();
        acked += lines
            .map_while(|l| l.ok())
            .filter(|l| l.contains("added"))
            .count() as u64;

        let mut v = e.open().unwrap();
        v.unlock(Auth::Password(&PW.into())).unwrap();
        let list = v.list(ListFilter::Active).unwrap();
        for m in &list {
            assert!(
                v.get(m.id)
                    .ok()
                    .unwrap()
                    .secrets
                    .body
                    .unwrap()
                    .expose()
                    .starts_with("假正文-")
            );
        }
        let n = list.len() as u64;
        assert!(n >= committed + acked, "已确认提交的 {acked} 条不能丢");
        assert!(
            n <= committed + acked + 1,
            "最多多出一条刚提交未来得及报告的"
        );
        committed = n;
    }
    assert!(committed > 0);
}
