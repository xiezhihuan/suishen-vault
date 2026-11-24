//! 凭据存放：默认系统凭据；没有系统凭据的服务器可用环境变量指定一个仅本人可读的文件。
use std::{fs, io::Write, path::PathBuf};
use zeroize::Zeroizing;

const SERVICE: &str = "dev.suishen.vault.bridge";

pub struct Store {
    name: String,
    file: Option<PathBuf>,
}

impl Store {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            file: std::env::var_os("SUISHEN_BRIDGE_DIR")
                .map(|d| PathBuf::from(d).join(format!("{name}.json"))),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, ()> {
        keyring::Entry::new(SERVICE, &self.name).map_err(|_| ())
    }

    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, ()> {
        match &self.file {
            Some(f) => fs::read(f).map_err(|_| ()),
            None => self.entry()?.get_secret().map_err(|_| ()),
        }
        .map(Zeroizing::new)
    }

    pub fn save(&self, data: &[u8]) -> Result<(), ()> {
        let Some(path) = &self.file else {
            return self.entry()?.set_secret(data).map_err(|_| ());
        };
        let tmp = path.with_extension("tmp");
        let _ = fs::remove_file(&tmp);
        let mut o = fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|_| ())?;
        f.write_all(data).map_err(|_| ())?;
        f.sync_all().map_err(|_| ())?;
        fs::rename(&tmp, path).map_err(|_| ())
    }
}
