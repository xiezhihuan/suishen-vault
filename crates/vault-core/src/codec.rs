//! 简单的长度前缀编码，用于备份、迁移包与自定义字段。解码对恶意输入安全失败。

use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    /// 写机密内容时须给出足够容量，避免扩容时在堆上留下未清零的旧缓冲。
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(n)))
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }

    pub(crate) fn len(&mut self, n: usize) -> Result<()> {
        self.u32(u32::try_from(n).map_err(|_| Error::TooLarge)?);
        Ok(())
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) -> Result<()> {
        self.len(v.len())?;
        self.raw(v);
        Ok(())
    }

    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self(b)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(Error::Tampered)?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        self.array::<1>().map(|a| a[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// 元素个数。每个元素至少占 `min_each` 字节，防止用虚假的个数诱导大量分配。
    pub(crate) fn count(&mut self, min_each: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > self.0.len() / min_each.max(1) {
            return Err(Error::Tampered);
        }
        Ok(n)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return Err(Error::Tampered);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    pub(crate) fn remaining_len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Tampered)
        }
    }
}
