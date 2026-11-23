//! 密码生成器。均匀取样，保证每个选中的字符类至少出现一次。

use crate::error::{Error, Result};
use crate::secret::{SecretString, random_below};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// 去掉易混字符（0 O o 1 l I |）。
    pub avoid_ambiguous: bool,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: true,
        }
    }
}

const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/|~";
const AMBIGUOUS: &str = "0Oo1lI|";

pub fn generate_password(o: &GeneratorOptions) -> Result<SecretString> {
    let classes: Vec<Vec<char>> = [
        (o.lowercase, "abcdefghijklmnopqrstuvwxyz"),
        (o.uppercase, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (o.digits, "0123456789"),
        (o.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, s)| {
        s.chars()
            .filter(|c| !o.avoid_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    })
    .collect();
    if classes.is_empty() || !(4..=256).contains(&o.length) {
        return Err(Error::InvalidGenerator);
    }
    let all: Vec<char> = classes.concat();
    // 整串重抽直到每类都有，分布在满足条件的串上仍是均匀的。
    // 长度至少 4、最多 4 类，期望重抽次数很小；上限只为防止意外死循环。
    for _ in 0..10_000 {
        let mut s = String::with_capacity(o.length);
        for _ in 0..o.length {
            s.push(all[random_below(all.len() as u32)? as usize]);
        }
        let s = SecretString::new(s);
        if classes
            .iter()
            .all(|c| s.expose().chars().any(|x| c.contains(&x)))
        {
            return Ok(s);
        }
    }
    Err(Error::Random)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn respects_options(
            length in 4usize..64,
            flags in any::<[bool; 5]>().prop_filter("至少一类", |f| f[..4].iter().any(|x| *x)),
        ) {
            let o = GeneratorOptions {
                length, lowercase: flags[0], uppercase: flags[1], digits: flags[2],
                symbols: flags[3], avoid_ambiguous: flags[4],
            };
            let p = generate_password(&o).unwrap();
            let p = p.expose();
            prop_assert_eq!(p.chars().count(), length);
            prop_assert_eq!(p.chars().any(|c| c.is_ascii_lowercase()), o.lowercase);
            prop_assert_eq!(p.chars().any(|c| c.is_ascii_uppercase()), o.uppercase);
            prop_assert_eq!(p.chars().any(|c| c.is_ascii_digit()), o.digits);
            prop_assert_eq!(p.chars().any(|c| SYMBOLS.contains(c)), o.symbols);
            if o.avoid_ambiguous {
                prop_assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
            }
        }
    }

    #[test]
    fn rejects_bad_options_and_does_not_repeat() {
        let none = GeneratorOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&none).err(),
            Some(Error::InvalidGenerator)
        );
        let short = GeneratorOptions {
            length: 3,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&short).err(),
            Some(Error::InvalidGenerator)
        );
        let d = GeneratorOptions::default();
        let a = generate_password(&d).unwrap();
        assert!(!a.ct_eq(generate_password(&d).unwrap().expose()));
    }
}
