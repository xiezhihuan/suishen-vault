//! 输入全部为合成的例文，不使用真实凭据。
use proptest::prelude::*;
use vault_core::paste::{
    Field::{self, *},
    Recognizer, Rules,
};

fn check(input: &str, expected: &[(usize, Field, &str)]) {
    let spans = Rules.recognize(input).unwrap();
    let mut offset = 0;
    for s in &spans {
        assert_eq!(s.start, offset);
        offset = s.end
    }
    assert_eq!(offset, input.len());
    let fields: Vec<_> = spans
        .iter()
        .filter(|s| s.kind != Syntax)
        .map(|s| (s.entry, s.kind, &input[s.start..s.end]))
        .collect();
    assert_eq!(fields, expected);
}

#[test]
fn labeled_matrix() {
    // 29 个标签，各自与六种分隔符组合，全部核对原文值。
    for (kind, label, value) in [
        (Title, "标题", "示例 甲"),
        (Title, "title", "Fake TITLE"),
        (Title, "名称", "示例站"),
        (Title, "Name", "A Site"),
        (Username, "用户名", "示例人"),
        (Username, "账号", "Ｆａｋｅ用户"),
        (Username, "帐号", "假帳戶"),
        (Username, "登录名", "FakeLogin"),
        (Username, "邮箱", "Fake.A@EXAMPLE.test"),
        (Username, "手机", "13800000000"),
        (Username, "手机号", "+8613800000000"),
        (Username, "USER", "Fake.U"),
        (Username, "username", "Fake-Login"),
        (Username, "login", "Foo偽"),
        (Username, "email", "fake+tag@example.test"),
        (Username, "phone", "+11234567890"),
        (Url, "网址", "https://示例.test/登"),
        (Url, "域名", "EXAMPLE.test"),
        (Url, "url", "http://fake.test:8080/login"),
        (Url, "Website", "example.test"),
        (Password, "密码", "  fake:a = 🔐  "),
        (Password, "口令", "“fake　pw”"),
        (Password, "PASSWORD", "'Fake: =🙂'"),
        (Password, "pwd", "=Fake="),
        (Password, "passwd", " 假  "),
        (Totp, "TOTP 密钥", "FAKEFAKEFAKEFAKE"),
        (Totp, "totp", "otpauth://totp/Fake?secret=FAKEFAKEFAKEFAKE"),
        (Note, "备注", "假备注：手工核对"),
        (Note, "notes", "Keep Quotes \"Ｈｉ\""),
    ] {
        for delimiter in [":", "：", "=", "＝", " ", "　"] {
            let input = format!("{label}{delimiter}{value}");
            check(&input, &[(0, kind, value)]);
        }
    }
}

#[test]
fn multiline_mixed_unknown_and_boundaries() {
    check(
        "标题:甲\r\nurl=EXAMPLE.test\r\n密码=  假🔐' =:  \r\n\r\n标题:乙 user=b password=x y",
        &[
            (0, Title, "甲"),
            (0, Url, "EXAMPLE.test"),
            (0, Password, "  假🔐' =:  "),
            (1, Title, "乙"),
            (1, Username, "b"),
            (1, Password, "x y"),
        ],
    );
    check(
        "xyz.test fake@example.test 假_pw",
        &[
            (0, Url, "xyz.test"),
            (0, Username, "fake@example.test"),
            (0, Unknown, "假_pw"),
        ],
    );
    check(
        "https://xyz.test\n13800000000\n  +乱 文?  ",
        &[
            (0, Url, "https://xyz.test"),
            (0, Username, "13800000000"),
            (0, Unknown, "  +乱 文?  "),
        ],
    );
    check(
        "密码:fake pass user:perhaps",
        &[(0, Unknown, "fake pass user:perhaps")],
    );
    check(
        "标题:甲\n网址:a.test\n标题:乙\n网址:b.test",
        &[
            (0, Title, "甲"),
            (0, Url, "a.test"),
            (1, Title, "乙"),
            (1, Url, "b.test"),
        ],
    );
    check(
        "🤖 ？？？\n🪴",
        &[(0, Unknown, "🤖 ？？？"), (0, Unknown, "🪴")],
    );
    check(
        "工作\texample.test\tfake-user\t =Fake:🙂  ",
        &[
            (0, Title, "工作"),
            (0, Url, "example.test"),
            (0, Username, "fake-user"),
            (0, Password, " =Fake:🙂  "),
        ],
    );
    check(
        "example.test\tfake-user\tFake",
        &[
            (0, Url, "example.test"),
            (0, Username, "fake-user"),
            (0, Password, "Fake"),
        ],
    );
    check("", &[]);
}

proptest! {
    #[test]
    fn ranges_are_a_lossless_partition(prefix in ".{0,70}",value in "[^\r\n]{1,90}",suffix in ".{0,80}"){
        let input=format!("{prefix}\n密码={value}\r\n{suffix}");
        let spans=Rules.recognize(&input).unwrap();let mut offset=0;
        for s in spans {
            prop_assert_eq!(s.start,offset);
            let slice=input.get(s.start..s.end).expect("合法 UTF-8 边界");
            prop_assert!(!slice.is_empty());
            if s.start==prefix.len()+1+"密码=".len(){prop_assert_eq!(slice,value.as_str());}
            offset=s.end;
        }
        prop_assert_eq!(offset,input.len());
    }
}
