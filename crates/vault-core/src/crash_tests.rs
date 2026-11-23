//! 断电模拟：在提交过程的每一步把数据库与日志文件原样拷走，
//! 再像断电重启那样打开拷贝。要求：要么是旧状态，要么是新状态，要么明确拒绝；
//! 绝不能打开成半新半旧。

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use proptest::test_runner::{Config, TestRunner};

use crate::clock::SystemClock;
use crate::error::Error;
use crate::fsutil::with_suffix;
use crate::model::{ItemDraft, ItemKind};
use crate::store::step;
use crate::vault::{Auth, ListFilter, Setup, Vault};

const PW: &str = "fake-master-鲸鱼-0001";

fn new_vault(path: &Path) -> Vault {
    let s = Setup::begin(&PW.into()).ok().unwrap();
    let key = s.recovery_key().expose().to_owned();
    let g: Vec<&str> = key.split('-').collect();
    let [a, b] = s.challenge().map(|i| g[i as usize]);
    s.confirm(path, [a, b], Arc::new(SystemClock::default()))
        .ok()
        .unwrap()
}

fn draft(tag: &str, i: usize) -> ItemDraft {
    let mut d = ItemDraft::new(ItemKind::Note, &format!("{tag}{i}"));
    // 足够大，逼 SQLite 在提交前就把页写进数据库文件
    d.secrets.body = Some(format!("{tag}-假正文-{i}-").repeat(400).as_str().into());
    d
}

/// 全部条目的标题与正文首段；任何一条读不出就报错。
fn state(v: &Vault) -> Result<BTreeSet<String>, Error> {
    v.list(ListFilter::Active)?
        .iter()
        .map(|m| {
            let body = v.get(m.id)?.secrets.body.ok_or(Error::Tampered)?;
            Ok(format!("{}|{}", m.title, body.expose()))
        })
        .collect()
}

fn reopen(path: &Path) -> Result<BTreeSet<String>, Error> {
    let mut v = Vault::open(path)?;
    v.unlock(Auth::Password(&PW.into()))?;
    state(&v)
}

struct Shot {
    db: Vec<u8>,
    journal: Option<Vec<u8>>,
    step: String,
}

fn shoot(path: &Path, step: &str) -> Shot {
    Shot {
        db: fs::read(path).unwrap(),
        journal: fs::read(with_suffix(path, "-journal")).ok(),
        step: step.to_owned(),
    }
}

fn lay(dir: &Path, name: &str, db: &[u8], journal: Option<&[u8]>) -> PathBuf {
    let p = dir.join(name);
    let j = with_suffix(&p, "-journal");
    let _ = fs::remove_file(&j);
    fs::write(&p, db).unwrap();
    if let Some(b) = journal {
        fs::write(&j, b).unwrap();
    }
    p
}

fn items(tag: &str) -> Vec<ItemDraft> {
    (0..12).map(|i| draft(tag, i)).collect()
}

/// 执行一次真实的 `Vault` 操作，在提交过程中逐步截取文件。返回（旧状态，新状态，截图）。
fn record(
    dir: &Path,
    op: impl FnOnce(&mut Vault),
) -> (BTreeSet<String>, BTreeSet<String>, Vec<Shot>) {
    let path = dir.join("v.svault");
    let mut v = new_vault(&path);
    v.add_many(&items("旧")).unwrap();
    let trash: Vec<_> = v.add_many(&items("弃")).unwrap();
    for id in trash {
        v.trash(id).unwrap();
    }
    let old = state(&v).unwrap();
    // 缓存只留几页，事务中途就会写库
    v.store_for_test()
        .conn_for_test()
        .execute_batch("PRAGMA cache_size = 4; PRAGMA cache_spill = 4;")
        .unwrap();
    let shots = Rc::new(RefCell::new(vec![shoot(&path, "before")]));
    let (sink, at) = (shots.clone(), path.clone());
    step::set(Some(Box::new(move |name| {
        sink.borrow_mut().push(shoot(&at, name));
    })));
    op(&mut v);
    step::set(None);
    shots.borrow_mut().push(shoot(&path, "after"));
    let new = state(&v).unwrap();
    drop(v);
    let shots = Rc::try_unwrap(shots).ok().unwrap().into_inner();
    (old, new, shots)
}

/// 新增 12 条。
fn add_batch(v: &mut Vault) {
    v.add_many(&items("新")).unwrap();
}

#[test]
fn power_loss_at_every_step_yields_old_or_new_state() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new, shots) = record(dir.path(), add_batch);
    assert!(old != new);
    let spilled = shots
        .iter()
        .filter(|s| s.step != "before" && s.step != "after" && s.db != shots[0].db)
        .count();
    assert!(
        shots.len() > 20 && spilled > 5,
        "事务中途应已有页写入数据库，否则测不到断电"
    );
    for s in &shots {
        // 事务中途的数据库与日志里同样没有明文
        let plain = "假正文".as_bytes();
        for bytes in [Some(&s.db), s.journal.as_ref()].into_iter().flatten() {
            assert!(!bytes.windows(plain.len()).any(|w| w == plain));
        }
        let p = lay(dir.path(), "shot.svault", &s.db, s.journal.as_deref());
        let got = reopen(&p).unwrap();
        let want = if s.step == "after" { &new } else { &old };
        assert!(got == *want, "{}", s.step);
    }
}

/// 其他会改多行的操作：清空回收站、单条修改、改主密码。
#[test]
fn power_loss_during_other_operations() {
    type Op = fn(&mut Vault);
    let ops: [(&str, Op); 3] = [
        ("清空回收站", |v| {
            v.empty_trash().unwrap();
        }),
        ("修改", |v| {
            let id = v.list(ListFilter::Active).unwrap()[0].id;
            v.update(id, &draft("改", 99)).unwrap();
        }),
        ("移入回收站", |v| {
            let id = v.list(ListFilter::Active).unwrap()[0].id;
            v.trash(id).unwrap();
        }),
    ];
    for (name, op) in ops {
        let dir = tempfile::tempdir().unwrap();
        let (old, new, shots) = record(dir.path(), op);
        assert!(shots.len() >= 3, "{name}");
        for s in &shots {
            let p = lay(dir.path(), "shot.svault", &s.db, s.journal.as_deref());
            let mut v = Vault::open(&p).unwrap();
            v.unlock(Auth::Password(&PW.into())).unwrap();
            let want = if s.step == "after" { &new } else { &old };
            assert!(state(&v).unwrap() == *want, "{name} {}", s.step);
            let trash = v.list(ListFilter::Trash).unwrap().len();
            assert!(
                matches!(
                    (name, s.step.as_str(), trash),
                    ("清空回收站", "after", 0)
                        | ("移入回收站", "after", 13)
                        | ("修改", _, 12)
                        | (
                            "清空回收站" | "移入回收站",
                            "before" | "delete" | "item" | "manifest",
                            12
                        )
                ),
                "{name} {} {trash}",
                s.step
            );
        }
    }
}

#[test]
fn damaged_files_are_rejected_or_consistent_never_mixed() {
    let dir = tempfile::tempdir().unwrap();
    let (old, new, shots) = record(dir.path(), add_batch);
    let mut outcomes = [0usize; 2];
    let mut check = |db: &[u8], j: Option<&[u8]>, what: &str| {
        let p = lay(dir.path(), "bad.svault", db, j);
        match reopen(&p) {
            Ok(s) => {
                assert!(s == old || s == new, "{what}：出现了半新半旧的状态");
                outcomes[0] += 1;
            }
            Err(_) => outcomes[1] += 1,
        }
    };
    // 日志丢失、截断、写坏：比真实断电更糟的情况
    for s in &shots {
        check(&s.db, None, "日志丢失");
        if let Some(j) = &s.journal {
            for k in 1..8 {
                check(&s.db, Some(&j[..j.len() * k / 8]), "日志截断");
            }
        }
    }
    // 数据库尾部没写全
    let last = &shots[shots.len() - 1].db;
    for k in 1..16 {
        check(&last[..last.len() * k / 16], None, "数据库截断");
        check(&last[..last.len() * k / 16 - 100], None, "数据库截断");
    }
    // 撕裂写：新旧页混合
    let first = &shots[0].db;
    for page in 0..first.len().min(last.len()) / 4096 {
        let mut mix = last.clone();
        let r = page * 4096..(page + 1) * 4096;
        mix[r.clone()].copy_from_slice(&first[r]);
        check(&mix, None, "单页回到旧内容");
    }
    assert!(outcomes[1] > 50, "多数损坏应当被拒绝：{outcomes:?}");
}

#[test]
fn random_byte_corruption_never_yields_wrong_data() {
    let dir = tempfile::tempdir().unwrap();
    let (_, new, shots) = record(dir.path(), add_batch);
    let good = shots[shots.len() - 1].db.clone();
    let mut runner = TestRunner::new(Config {
        cases: 150,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(
            &proptest::collection::vec((0..good.len(), 1u8..=255), 1..4),
            |edits| {
                let mut bad = good.clone();
                for (i, x) in edits {
                    bad[i] ^= x;
                }
                let p = lay(dir.path(), "flip.svault", &bad, None);
                // 改到空闲字节或退避计数时仍可能打开，但内容必须完全正确
                if let Ok(s) = reopen(&p) {
                    assert!(s == new);
                }
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn interrupted_creation_leaves_no_half_vault() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.svault");
    // 断电残留的临时文件不影响重新创建，也不会被当成密库
    fs::write(
        dir.path().join(".v.svault.tmp-00"),
        b"SQLite format 3\0half",
    )
    .unwrap();
    assert!(matches!(Vault::open(&path), Err(Error::NotFound)));
    drop(new_vault(&path));
    assert!(reopen(&path).unwrap().is_empty());
}
