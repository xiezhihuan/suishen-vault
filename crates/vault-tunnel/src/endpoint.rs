use crate::{Result, TunnelError};

/// 跳板地址。除回环外只允许 HTTPS。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    tls: bool,
}

impl Endpoint {
    /// 接受 `relay.example.com`、`https://relay.example.com:8443`，以及仅限回环的 `http://127.0.0.1:端口`。
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let (tls, rest) = match text.split_once("://") {
            Some(("https", r)) => (true, r),
            Some(("http", r)) => (false, r),
            Some(_) => return Err(TunnelError),
            None => (true, text),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().ok().filter(|p| *p != 0).ok_or(TunnelError)?),
            None => (rest, if tls { 443 } else { 80 }),
        };
        let label = |l: &str| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        };
        if host.len() > 253 || !host.split('.').all(label) {
            return Err(TunnelError);
        }
        if !tls && !matches!(host, "127.0.0.1" | "localhost") {
            return Err(TunnelError);
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            tls,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn tls(&self) -> bool {
        self.tls
    }

    /// 即 HTTP `Host`：默认端口省略。身份握手的签名绑定它。
    pub fn authority(&self) -> String {
        match (self.tls, self.port) {
            (true, 443) | (false, 80) => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        }
    }

    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{}", self.authority())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_loopback_http_only() {
        for (text, url) in [
            ("relay.example.com", "https://relay.example.com"),
            (" Relay.Example.com/ ", "https://relay.example.com"),
            ("https://relay.example.com:443", "https://relay.example.com"),
            ("https://localhost:8443", "https://localhost:8443"),
            ("http://127.0.0.1:7470", "http://127.0.0.1:7470"),
        ] {
            let e = Endpoint::parse(text).unwrap();
            assert_eq!(e.url(), url);
            assert_eq!(Endpoint::parse(&e.url()).unwrap(), e);
        }
        for bad in [
            "",
            "http://relay.example.com",
            "ftp://relay.example.com",
            "https://user@relay.example.com",
            "https://relay.example.com/path",
            "https://relay.example.com:0",
            "https://relay.example.com:99999",
            "https://a b",
            "https://-a.com",
            "relay.example.com?x=1",
            "https://relay.example.com\r\nX: y",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
}
