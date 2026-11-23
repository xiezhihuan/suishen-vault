//! 1 万条下的检索耗时，只在发布版断言。AC-VLT-04
#![cfg(not(debug_assertions))]
mod common;
use common::*;
use std::time::{Duration, Instant};
use vault_core::search::ClientId;

#[test]
fn ten_thousand_items_search_under_200ms() {
    let (e, mut v) = new_env();
    let names = [
        "招商银行",
        "GitHub",
        "公司邮箱",
        "路由器",
        "淘宝",
        "重庆社保",
        "Cloudflare",
        "身份证照片",
    ];
    let mut csv = String::from("name,url,username,password,note\n");
    for i in 0..10_000 {
        csv += &format!(
            "{}{i},https://site{i}.example.test/login,fakeuser{i}@example.test,Fake-Pw-{i},这是第{i}条的备注：{}\n",
            names[i % names.len()],
            "客厅书房办公室的各种说明文字".repeat(5)
        );
    }
    std::fs::write(e.file("in.csv"), csv).unwrap();
    let t = Instant::now();
    assert_eq!(
        v.import_csv(&e.file("in.csv"), None).unwrap().imported,
        10_000
    );
    let import = t.elapsed();
    drop(v);

    let t = Instant::now();
    let mut v = e.unlocked();
    let unlock = t.elapsed();

    let t = Instant::now();
    v.search("预热", 5).unwrap();
    let first = t.elapsed();

    let mut worst = first;
    for q in [
        "招商银行",
        "zhaoshangyinhang",
        "zsyh",
        "gihtub",
        "site777.example.test",
        "公司那个邮箱账号",
        "fakeuser9999",
        "身份证",
        "办公室的说明",
        "招商银行信用卡网银登录",
        "cloudflear 777",
        "财务 客厅 笔记",
    ] {
        let t = Instant::now();
        v.search(q, 50).unwrap();
        worst = worst.max(t.elapsed());
        let t = Instant::now();
        v.ai().unwrap().search(ClientId([1; 16]), q).unwrap();
        e.clock.advance(60_000);
        worst = worst.max(t.elapsed());
    }
    let t = Instant::now();
    v.add(&note("再加一条", "假")).unwrap();
    let add = t.elapsed();
    let line = format!(
        "导入 {import:?}；解锁 {unlock:?}；首次搜索{first:?}；最慢搜索 {worst:?}；新增一条 {add:?}\n"
    );
    use std::io::Write;
    std::io::stdout().write_all(line.as_bytes()).unwrap();
    assert!(worst < Duration::from_millis(200), "{worst:?}");
}
