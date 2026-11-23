//! 直接扫描磁盘字节，断言找不到任何假明文。AC-KEY-04、AC-BAK-01、AC-LOG-01 的密库侧
mod common;
use common::*;
use std::path::Path;
use vault_core::model::{AiField, CustomField, ItemDraft, ItemKind};
use vault_core::*;

/// 每一段都带独特标记。
const MARKS: &[&str] = &[
    "标题猎户座",
    "TitleOrion7781",
    "tagvega5512",
    "标签织女星",
    "hintsirius9034",
    "提示天狼星",
    "domainaltair3321",
    "acctdeneb6610",
    "PwRigel#4478zz",
    "notebetelgeuse2205",
    "备注参宿四",
    "bodypolaris8897",
    "正文北极星",
    "custnamecapella1183",
    "custvalarcturus7752",
    "NRUWC3DFNRZG6ZLT",
    "urlpathantares4409",
    "oldpwspica9921",
    "trashedprocyon3340",
];

fn base64(b: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks_exact(3) {
        let n = u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
        for k in (0..4).rev() {
            s.push(T[(n >> (6 * k) & 63) as usize] as char);
        }
    }
    s
}

/// 明文可能的各种样子：UTF-8、大小写、UTF-16、十六进制、Base64 三种对齐、反序。
fn encodings(m: &str) -> Vec<Vec<u8>> {
    let b = m.as_bytes();
    let u16s = |le: bool| -> Vec<u8> {
        m.encode_utf16()
            .flat_map(|x| if le { x.to_le_bytes() } else { x.to_be_bytes() })
            .collect()
    };
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let mut v = vec![
        b.to_vec(),
        m.to_lowercase().into_bytes(),
        m.to_uppercase().into_bytes(),
        u16s(true),
        u16s(false),
        hex.to_uppercase().into_bytes(),
        hex.into_bytes(),
        b.iter().rev().copied().collect(),
    ];
    v.extend((0..3).map(|k| base64(&b[k..]).into_bytes()));
    v
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// 扫描目录下所有文件（含日志、临时文件、备份、迁移包）。
fn scan(dir: &Path, extra: &[String]) -> usize {
    let mut files = 0;
    for f in std::fs::read_dir(dir).unwrap() {
        let p = f.unwrap().path();
        let bytes = std::fs::read(&p).unwrap();
        files += 1;
        for m in MARKS
            .iter()
            .copied()
            .chain(extra.iter().map(String::as_str))
        {
            for enc in encodings(m) {
                assert!(!find(&bytes, &enc), "{} 中发现 {m}", p.display());
            }
        }
    }
    files
}

fn drafts() -> Vec<ItemDraft> {
    let mut a = ItemDraft::new(ItemKind::Login, "标题猎户座 TitleOrion7781");
    a.tags = vec!["tagvega5512".into(), "标签织女星".into()];
    a.hint = "hintsirius9034 提示天狼星".into();
    a.domains = vec!["domainaltair3321.example.test".into()];
    a.secrets.username = Some("acctdeneb6610".into());
    a.secrets.password = Some("PwRigel#4478zz".into());
    a.secrets.note = Some("notebetelgeuse2205 备注参宿四".into());
    a.secrets.totp = Some("NRUWC3DFNRZG6ZLT".into());
    a.secrets.urls = vec!["https://domainaltair3321.example.test/urlpathantares4409".into()];
    a.secrets.custom = vec![CustomField {
        name: "custnamecapella1183".into(),
        value: "custvalarcturus7752".into(),
    }];
    vec![a, note("TitleOrion7781 笔记", "bodypolaris8897 正文北极星")]
}

#[test]
fn scanner_itself_works() {
    let dir = tempfile::tempdir().unwrap();
    for (i, enc) in encodings("PwRigel#4478zz").into_iter().enumerate() {
        std::fs::write(dir.path().join("x"), [&b"abc"[..], &enc, b"def"].concat()).unwrap();
        let r = std::panic::catch_unwind(|| scan(dir.path(), &[]));
        assert!(r.is_err(), "扫描器应能发现第 {i} 种编码");
    }
}

#[test]
fn no_plaintext_on_disk_through_the_whole_life_cycle() {
    let (e, mut v) = new_env();
    // 主密码与恢复密钥也不得落盘
    let mut extra = vec![
        PW.to_owned(),
        PW2.to_owned(),
        e.recovery.clone(),
        e.recovery.replace('-', ""),
    ];
    let ids: Vec<_> = drafts().iter().map(|d| v.add(d).unwrap()).collect();
    scan(e.dir.path(), &extra);

    // 修改、回收站、物理删除、搜索、授权
    let mut d = v.get(ids[0]).ok().unwrap().to_draft();
    d.secrets.password = Some("oldpwspica9921".into());
    v.update(ids[0], &d).unwrap();
    let t = v
        .add(&note("trashedprocyon3340", "trashedprocyon3340x"))
        .unwrap();
    v.trash(t).unwrap();
    v.purge(t).unwrap();
    v.search("acctdeneb6610", 5).unwrap();
    v.ai()
        .unwrap()
        .search(search::ClientId([0; 16]), "猎户座")
        .unwrap();
    v.reveal_for_grant(ids[0], &[AiField::Password], Auth::Password(&PW.into()))
        .ok()
        .unwrap();
    scan(e.dir.path(), &extra);

    v.change_password(&PW.into(), &PW2.into()).unwrap();
    v.lock(LockMode::KeepServing);
    scan(e.dir.path(), &extra);
    let _ = v.unlock(Auth::Password(&PW.into()));
    v.unlock(Auth::Password(&PW2.into())).unwrap();

    // 备份、迁移
    v.export_backup(&e.file("b.svbak")).unwrap();
    restore_backup(
        &e.file("b.svbak"),
        &e.file("r.svault"),
        RestoreAuth::Password(&PW2.into()),
    )
    .unwrap();
    let code = v
        .begin_migration(Auth::Password(&PW2.into()), &e.file("m.svmig"))
        .ok()
        .unwrap();
    extra.push(code.expose().to_owned());
    extra.push(code.expose().replace('-', ""));
    let imp = import_migration(
        &e.file("m.svmig"),
        &MigrationCode::parse(code.expose()).ok().unwrap(),
        RestoreAuth::Password(&PW2.into()),
        &e.file("n.svault"),
        e.clock.clone(),
    )
    .ok()
    .unwrap();
    extra.push(imp.completion_code.expose().to_owned());
    extra.push(imp.completion_code.expose().replace('-', ""));
    assert!(scan(e.dir.path(), &extra) >= 5);
    drop((v, imp));
    assert!(scan(e.dir.path(), &extra) >= 5);
}

#[test]
fn database_does_not_reveal_kinds_or_secret_lengths() {
    // 两条账号只有密码长度不同；密文长度应相同
    let (e, mut v) = new_env();
    v.add(&login("甲", "https://x.example.test", "fakeuser", "Fa-1"))
        .unwrap();
    v.add(&login(
        "乙",
        "https://x.example.test",
        "fakeuser",
        "Fake-Password-Forty-Characters-Long-00001",
    ))
    .unwrap();
    drop(v);
    sql(&e.path(), |c| {
        let mut per: std::collections::BTreeMap<Vec<u8>, Vec<i64>> = Default::default();
        let mut s = c
            .prepare("SELECT item_id, length(blob) FROM item_field")
            .unwrap();
        let rows = s
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
            .unwrap();
        for r in rows {
            let (k, n) = r.unwrap();
            per.entry(k).or_default().push(n);
        }
        let mut v: Vec<_> = per.into_values().collect();
        v.iter_mut().for_each(|x| x.sort());
        assert_eq!(v[0], v[1]);
    });
}

#[test]
fn errors_never_contain_input() {
    let (_e, mut v) = new_env();
    let mut msgs = Vec::new();
    let mut d = login(
        "PwRigel#4478zz",
        "https://a.example.test",
        "acctdeneb6610",
        "PwRigel#4478zz",
    );
    let mut push = |e: Error| msgs.push(format!("{e} {e:?}"));
    push(err(v.add(&d)));
    d.title = "好".into();
    d.secrets.totp = Some("PwRigel#4478zz".into());
    push(err(v.add(&d)));
    push(err(v.unlock(Auth::Password(&"PwRigel#4478zz".into()))));
    push(err(RecoveryKey::parse("PwRigel#4478zz")));
    push(err(Setup::begin(&"PwRigel".into())));
    for m in msgs {
        for mark in MARKS {
            assert!(!m.contains(mark), "{m}");
        }
    }
}
