//! CSV 解析。用 `csv-core` 而不是 `csv`：缓冲由自己提供，用完可清零。

use csv_core::{ReadRecordResult, ReaderBuilder};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SecretString;

pub(crate) type Row = Vec<SecretString>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `""` 表示引号。
    DoubledQuotes,
    /// KeePass 1.x：`\"` 与 `\\`。
    Backslash,
}

pub(crate) fn parse(text: &[u8], dialect: Dialect) -> Result<Vec<Row>> {
    let mut rdr = match dialect {
        Dialect::DoubledQuotes => ReaderBuilder::new().build(),
        Dialect::Backslash => ReaderBuilder::new()
            .double_quote(false)
            .escape(Some(b'\\'))
            .build(),
    };
    // 输出不会比输入长，一次分配到位，避免扩容留下残片
    let mut out = Zeroizing::new(vec![0u8; text.len() + 1]);
    let mut ends = vec![0usize; 1024];
    let mut rows = Vec::new();
    let mut input = text;
    loop {
        let (mut wrote, mut fields) = (0, 0);
        let end = loop {
            let (res, nin, nout, nend) =
                rdr.read_record(input, &mut out[wrote..], &mut ends[fields..]);
            input = &input[nin..];
            wrote += nout;
            fields += nend;
            match res {
                // 再给一次空输入表示结束
                ReadRecordResult::InputEmpty => {}
                // 列数过多不是任何已知格式
                ReadRecordResult::OutputFull | ReadRecordResult::OutputEndsFull => {
                    return Err(Error::CsvFormat);
                }
                ReadRecordResult::Record => break false,
                ReadRecordResult::End => break true,
            }
        };
        if end {
            return Ok(rows);
        }
        let mut row = Row::with_capacity(fields);
        let mut start = 0;
        for e in &ends[..fields] {
            let cell = std::str::from_utf8(&out[start..*e]).map_err(|_| Error::CsvEncoding)?;
            row.push(cell.into());
            start = *e;
        }
        rows.push(row);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cells(text: &str, d: Dialect) -> Vec<Vec<String>> {
        parse(text.as_bytes(), d)
            .unwrap()
            .iter()
            .map(|r| r.iter().map(|c| c.expose().to_owned()).collect())
            .collect()
    }

    #[test]
    fn dialects() {
        assert_eq!(
            cells("a,b\r\n\"x\"\"y\",\"1\n2\"\n", Dialect::DoubledQuotes),
            [vec!["a", "b"], vec!["x\"y", "1\n2"]]
        );
        assert_eq!(
            cells("\"a\",\"b\"\r\n\"x\\\"y\",\"c\\\\d\"", Dialect::Backslash),
            [vec!["a", "b"], vec!["x\"y", "c\\d"]]
        );
        assert!(cells("", Dialect::DoubledQuotes).is_empty());
    }

    proptest! {
        #[test]
        fn round_trips_any_text(rows in prop::collection::vec(
            prop::collection::vec("[^\\x00]{0,12}", 2..5), 1..6)) {
            let text: String = rows.iter().map(|r| {
                r.iter().map(|c| format!("\"{}\"", c.replace('"', "\"\"")))
                    .collect::<Vec<_>>().join(",") + "\n"
            }).collect();
            prop_assert_eq!(cells(&text, Dialect::DoubledQuotes), rows);
        }

        #[test]
        fn never_panics(b in prop::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse(&b, Dialect::DoubledQuotes);
            let _ = parse(&b, Dialect::Backslash);
        }
    }
}
