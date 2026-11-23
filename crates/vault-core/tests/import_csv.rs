//! CSV 导入。内容全部是编造的。
mod common;
use common::*;
use proptest::prelude::*;
use vault_core::import::*;
use vault_core::model::ItemKind;
use vault_core::*;

fn run(csv: &[u8]) -> (Env, Vault, ImportReport) {
    let (e, mut v) = new_env();
    let p = e.file("in.csv");
    std::fs::write(&p, csv).unwrap();
    let r = v.import_csv(&p, None).unwrap();
    (e, v, r)
}

fn by_title(v: &Vault, t: &str) -> model::Item {
    let id = v
        .list(ListFilter::Active)
        .unwrap()
        .into_iter()
        .find(|m| m.title == t)
        .unwrap_or_else(|| panic!("没有 {t}"))
        .id;
    v.get(id).ok().unwrap()
}

#[test]
fn chrome() {
    let csv = "\u{FEFF}name,url,username,password,note\r\n\
        示例站,https://www.site.example.test/login?a=1,fakeuser01,\"Fake,\"\"Pw\"\" 1\",\"第一行\n第二行\"\r\n\
        ,https://notitle.example.test/,fakeuser02, Fake Pw 2 ,\r\n\
        ,,,,\r\n";
    let (e, v, r) = run(csv.as_bytes());
    assert_eq!(r.format, CsvFormat::Chrome);
    assert_eq!((r.imported, r.blank, r.rejected.len()), (2, 1, 0));
    assert_eq!(r.adjusted, [(2, Adjustment::TitleGenerated)]);
    let i = by_title(&v, "示例站");
    assert_eq!(i.meta.domains, ["site.example.test"]);
    assert!(i.secrets.password.unwrap().ct_eq("Fake,\"Pw\" 1"));
    assert!(i.secrets.note.unwrap().ct_eq("第一行\n第二行"));
    // 密码首尾空格原样保留
    let i = by_title(&v, "notitle.example.test");
    assert!(i.secrets.password.unwrap().ct_eq(" Fake Pw 2 "));

    // 提示并删除明文 CSV
    assert_eq!(r.delete_prompt(), DELETE_CSV_PROMPT);
    assert!(r.source().exists(), "不经用户同意不删除");
    r.delete_source().unwrap();
    assert!(!e.file("in.csv").exists());
    assert_eq!(err(r.delete_source()), Error::NotFound);
}

#[test]
fn whitespace_only_password_survives_import() {
    let (_env, vault, report) = run(b"name,url,username,password\n,,,\t\n");
    assert_eq!((report.imported, report.blank), (1, 0));
    let id = vault.list(ListFilter::Active).unwrap()[0].id;
    assert!(vault.get(id).unwrap().secrets.password.unwrap().ct_eq("\t"));
}

#[test]
fn bitwarden() {
    let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
        工作,1,login,代码托管,假备注,\"问题: 答案\n无冒号\",0,\"https://a.example.test,https://b.example.test/x,y\",fakeuser01,Fake-Pw-1,GEZDGNBVGY3TQOJQ\n\
        ,,note,保险单,\"编号 FAKE-001\",,0,,,,\n\
        ,,login,坏TOTP,,,0,,fakeuser02,Fake-Pw-2,steam://FAKE\n\
        ,,login,只有标题,,,0,,,,\n";
    let (_e, v, r) = run(csv.as_bytes());
    assert_eq!(r.format, CsvFormat::Bitwarden);
    assert_eq!((r.imported, r.rejected.len()), (4, 0));
    let i = by_title(&v, "代码托管");
    assert_eq!(i.meta.tags, ["工作"]);
    assert_eq!(i.secrets.urls.len(), 2);
    assert!(i.secrets.urls[1].ct_eq("https://b.example.test/x,y"));
    assert!(i.secrets.totp.is_some());
    assert_eq!(i.secrets.custom.len(), 2);
    assert!(i.secrets.custom[0].name.ct_eq("问题") && i.secrets.custom[0].value.ct_eq("答案"));
    let i = by_title(&v, "保险单");
    assert_eq!(i.meta.kind, ItemKind::Note);
    assert!(i.secrets.body.unwrap().ct_eq("编号 FAKE-001"));
    // 认不出的 TOTP 不丢，挪到自定义字段
    let i = by_title(&v, "坏TOTP");
    assert!(i.secrets.totp.is_none());
    assert!(i.secrets.custom[0].value.ct_eq("steam://FAKE"));
    assert!(r.adjusted.contains(&(3, Adjustment::TotpMoved)));
    assert_eq!(by_title(&v, "只有标题").meta.kind, ItemKind::Note);
}

#[test]
fn keepass_backslash_dialect() {
    let csv = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\r\n\
        \"路由器\",\"fakeadmin1\",\"Fake\\\"Pw\\\\1\",\"http://192.168.1.1\",\"行一\r\n行二\"\r\n";
    let (_e, v, r) = run(csv.as_bytes());
    assert_eq!(r.format, CsvFormat::KeePass);
    let i = by_title(&v, "路由器");
    assert!(i.secrets.password.unwrap().ct_eq("Fake\"Pw\\1"));
    assert_eq!(i.meta.domains, ["192.168.1.1"]);
}

#[test]
fn keepassxc() {
    let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\",\"自加列\"\n\
        \"Root/银行/信用卡\",\"某行\",\"fakeuser01\",\"Fake\\Pw\"\"1\",\"https://bank.example.test\",\"\",\"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=30&digits=6\",\"0\",\"2026-01-01T00:00:00Z\",\"2026-01-01T00:00:00Z\",\"额外\"\n";
    let (_e, v, r) = run(csv.as_bytes());
    assert_eq!(r.format, CsvFormat::KeePassXc);
    let i = by_title(&v, "某行");
    assert_eq!(i.meta.tags, ["银行", "信用卡"]);
    assert!(i.secrets.password.unwrap().ct_eq("Fake\\Pw\"1"));
    assert!(i.secrets.totp.is_some());
    assert!(i.secrets.custom[0].name.ct_eq("自加列"));
    assert_eq!(r.adjusted, [(1, Adjustment::ExtraKept)]);
}

// AC-VLT-08 在导入时的处理：不拒绝、不丢失，机密挪到机密字段
#[test]
fn secrets_in_titles_tags_and_domains_are_moved_not_lost() {
    let csv = "Group,Title,Username,Password,URL,Notes\n\
        Root/Fake-Pw-1,fake.user@example.test 的号,fake.user@example.test,Fake-Pw-1,https://a.example.test,\n\
        Root,内网,admin,Fake-Pw-2,https://admin.example.test/,\n\
        Root,Fake-Pw-3,u,Fake-Pw-3,,\n";
    let (_e, mut v, r) = run(csv.as_bytes());
    assert_eq!((r.imported, r.rejected.len()), (3, 0));
    for a in [
        Adjustment::TitleMoved,
        Adjustment::TagMoved,
        Adjustment::DomainOmitted,
    ] {
        assert!(r.adjusted.iter().any(|x| x.1 == a), "{a:?}");
    }
    let i = by_title(&v, "a.example.test");
    assert!(i.meta.tags.is_empty());
    assert!(
        i.secrets
            .custom
            .iter()
            .any(|c| c.value.ct_eq("fake.user@example.test 的号"))
    );
    let i = by_title(&v, "内网");
    assert!(i.meta.domains.is_empty());
    assert!(i.secrets.urls[0].ct_eq("https://admin.example.test/"));
    by_title(&v, "导入条目 3");
    // 导入得到的条目能直接打开编辑并保存
    for m in v.list(ListFilter::Active).unwrap() {
        let d = v.get(m.id).ok().unwrap().to_draft();
        if m.title != "内网" {
            v.update(m.id, &d).unwrap();
        }
    }
}

#[test]
fn bad_rows_are_reported_and_prompt_warns() {
    let csv = "name,url,username,password\n好,https://a.example.test,fakeuser,Fake-1\n少列,x\n多,列,a,b,c,d\n";
    let (_e, v, r) = run(csv.as_bytes());
    assert_eq!(r.imported, 1);
    assert_eq!(
        r.rejected,
        [
            (2, RejectReason::ColumnCount),
            (3, RejectReason::ColumnCount)
        ]
    );
    assert_eq!(r.delete_prompt(), DELETE_CSV_PROMPT_PARTIAL);
    assert_eq!(v.list(ListFilter::Active).unwrap().len(), 1);
}

#[test]
fn unrecognized_files_change_nothing() {
    let (e, mut v) = new_env();
    let p = e.file("x.csv");
    for (bytes, want) in [
        (&b""[..], Error::CsvFormat),
        (b"a,b,c\n1,2,3\n", Error::CsvFormat),
        (
            b"name,url,username,password\n\xB5\xC7\xC2\xBC,,,\n",
            Error::CsvEncoding,
        ),
    ] {
        std::fs::write(&p, bytes).unwrap();
        assert_eq!(err(v.import_csv(&p, None)), want);
    }
    std::fs::write(&p, "name,url,username,password\na,b,c,d\n").unwrap();
    assert_eq!(
        err(v.import_csv(&p, Some(CsvFormat::KeePass))),
        Error::CsvFormat
    );
    assert!(v.list(ListFilter::Active).unwrap().is_empty());
    v.lock(LockMode::Full);
    assert_eq!(err(v.import_csv(&p, None)), Error::Locked);
}

#[test]
fn changed_csv_is_not_deleted() {
    let (e, _v, r) = run(b"name,url,username,password\na,https://a.example.test,fakeuser,Fake-1\n");
    std::fs::write(e.file("in.csv"), b"something else").unwrap();
    assert_eq!(err(r.delete_source()), Error::SourceChanged);
    assert!(e.file("in.csv").exists());
}

#[test]
fn report_contains_no_content() {
    let (_e, _v, r) =
        run(b"name,url,username,password\nFake-Pw-9,https://a.example.test,fakeuser,Fake-Pw-9\n");
    let text = format!("{r:?}");
    assert!(!text.contains("Fake-Pw-9") && !text.contains("fakeuser"));
}

/// 任意内容的 Chrome CSV：要么导入并能原样取回密码，要么在报告里列出。
#[test]
fn arbitrary_rows_are_never_silently_lost() {
    let (e, v) = new_env();
    let v = std::cell::RefCell::new(v);
    let p = e.file("in.csv");
    let cell = "[^\\x00]{0,30}";
    let strat = proptest::collection::vec((cell, cell, cell, cell), 1..6);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 40,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    runner
        .run(&strat, |rows| {
            let mut v = v.borrow_mut();
            let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
            let mut text = String::from("name,url,username,password\n");
            for (a, b, c, d) in &rows {
                text += &format!("{},{},{},{}\n", q(a), q(b), q(c), q(d));
            }
            std::fs::write(&p, &text).unwrap();
            let before: Vec<_> = v
                .list(ListFilter::Active)
                .unwrap()
                .iter()
                .map(|m| m.id)
                .collect();
            let r = v.import_csv(&p, None).unwrap();
            prop_assert_eq!(r.imported + r.blank + r.rejected.len(), rows.len());
            prop_assert!(r.rejected.is_empty(), "{:?}", r.rejected);
            let mut got: Vec<String> = v
                .list(ListFilter::Active)
                .unwrap()
                .iter()
                .filter(|m| !before.contains(&m.id))
                .filter_map(|m| {
                    v.get(m.id)
                        .ok()
                        .unwrap()
                        .secrets
                        .password
                        .map(|p| p.expose().to_owned())
                })
                .collect();
            let mut want: Vec<String> = rows
                .iter()
                .map(|r| r.3.clone())
                .filter(|p| !p.is_empty())
                .collect();
            got.sort();
            want.sort();
            prop_assert_eq!(got, want);
            Ok(())
        })
        .unwrap();
}
