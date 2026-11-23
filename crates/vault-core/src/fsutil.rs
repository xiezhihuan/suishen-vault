//! 文件操作：原子写入、权限、清除。

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::model::hex;
use crate::secret::random_array;

/// 独占新建，仅本用户可读写。
pub(crate) fn create_private(path: &Path) -> Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// 同目录的临时文件名，保证改名是原子的。
pub(crate) fn temp_sibling(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().ok_or(Error::NotFound)?;
    let mut t = std::ffi::OsString::from(".");
    t.push(name);
    t.push(format!(".tmp-{}", hex(&random_array::<8>()?)));
    Ok(parent_of(path).join(t))
}

pub(crate) fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(parent_of(path))?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// 把写好的临时文件改名为目标。目标已存在时拒绝，绝不覆盖。
pub(crate) fn publish(tmp: &Path, dest: &Path) -> Result<()> {
    if fs::symlink_metadata(dest).is_ok() {
        return Err(Error::AlreadyExists);
    }
    tempfile::TempPath::try_from_path(tmp)?
        .persist_noclobber(dest)
        .map_err(|e| Error::from(e.error))?;
    sync_dir(dest)
}

/// 临时文件守卫：没有成功发布就删除。
pub(crate) struct TempFile(pub PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_file(with_suffix(&self.0, "-journal"));
    }
}

pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// 完整写入并落盘后才出现在目标位置；中途断电只会留下临时文件。
pub(crate) fn write_new_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    if fs::symlink_metadata(dest).is_ok() {
        return Err(Error::AlreadyExists);
    }
    let tmp = TempFile(temp_sibling(dest)?);
    let mut f = create_private(&tmp.0)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    publish(&tmp.0, dest)
}

/// 读取全文，有大小上限。缓冲一次分配到位并在丢弃时清零。
pub(crate) fn read_limited(path: &Path, max: u64) -> Result<Zeroizing<Vec<u8>>> {
    let f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > max {
        return Err(Error::TooLarge);
    }
    let cap = usize::try_from(len).map_err(|_| Error::TooLarge)?;
    let mut buf = Zeroizing::new(vec![0; cap]);
    let mut f = f;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// 覆写后删除。闪存与写时复制文件系统上无法保证物理擦除。
pub(crate) fn overwrite_and_remove(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.is_file() {
        let mut f = OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;
        let zeros = [0u8; 8192];
        let mut left = meta.len();
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    sync_dir(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_never_overwrites_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        write_new_atomic(&p, b"one").unwrap();
        assert_eq!(write_new_atomic(&p, b"two"), Err(Error::AlreadyExists));
        assert_eq!(fs::read(&p).unwrap(), b"one");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        overwrite_and_remove(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn size_limit_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        fs::write(&p, [0; 10]).unwrap();
        assert_eq!(read_limited(&p, 9).err(), Some(Error::TooLarge));
        assert_eq!(read_limited(&p, 10).unwrap().len(), 10);
    }
}
