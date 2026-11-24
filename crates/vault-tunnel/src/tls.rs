//! 两层 TLS，都只开 1.3，密码学提供者为 ring。
//!
//! - 外层：到反向代理的 HTTPS，按公开 CA（或用户指定的 CA）校验主机名。
//! - 内层：桥接与设备之间，用 RFC 7250 裸公钥，双方都只认配对时固定的 Ed25519 公钥。
use crate::{Endpoint, Identity, PublicKey, Result, TunnelError};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, RootCertStore,
    ServerConfig, SignatureScheme,
    client::{
        AlwaysResolvesClientRawPublicKeys, Resumption,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, ring, verify_tls13_signature_with_raw_key,
    },
    pki_types::{
        CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
        pem::PemObject,
    },
    server::{
        AlwaysResolvesServerRawPublicKeys, NoServerSessionStorage,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
    version::TLS13,
};
use std::{fmt, sync::Arc};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

/// 内层连接使用的主机名，不对应任何真实地址。
pub const DEVICE_HOST: &str = "device.svault.invalid";
/// 自定义 CA 证书的大小上限（PEM）。
pub const MAX_CA_PEM: usize = 2048;

/// Ed25519 公钥的 SubjectPublicKeyInfo 固定前缀（RFC 8410）。
const SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn algorithms() -> WebPkiSupportedAlgorithms {
    ring::default_provider().signature_verification_algorithms
}

fn raw_key(cert: &[u8]) -> Option<PublicKey> {
    cert.strip_prefix(&SPKI)?.try_into().ok()
}

fn certified(me: &Identity) -> Result<Arc<CertifiedKey>> {
    let key = ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(me.pkcs8()))
        .map_err(|_| TunnelError)?;
    let spki = [&SPKI[..], &me.public()].concat();
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki)],
        key,
    )))
}

fn check_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, Error> {
    verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(cert.as_ref()),
        dss,
        &algorithms(),
    )
}

const NO_TLS12: Error = Error::General(String::new());
fn unknown_key() -> Error {
    Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

#[derive(Debug)]
struct PinnedDevice(PublicKey);

impl ServerCertVerifier for PinnedDevice {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        (raw_key(cert) == Some(self.0))
            .then(ServerCertVerified::assertion)
            .ok_or_else(unknown_key)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Err(NO_TLS12)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        check_signature(m, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// 判断某个桥接公钥此刻是否允许连入。
pub type AllowKey = Arc<dyn Fn(&PublicKey) -> bool + Send + Sync>;

struct PinnedBridges(AllowKey);

impl fmt::Debug for PinnedBridges {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PinnedBridges")
    }
}

impl ClientCertVerifier for PinnedBridges {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        raw_key(cert)
            .filter(|k| (self.0)(k))
            .map(|_| ClientCertVerified::assertion())
            .ok_or_else(unknown_key)
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Err(NO_TLS12)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        check_signature(m, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// 桥接侧的内层握手。
pub async fn bridge_connect<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    me: &Identity,
    device: PublicKey,
) -> Result<client::TlsStream<S>> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| TunnelError)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedDevice(device)))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(certified(
            me,
        )?)));
    config.resumption = Resumption::disabled();
    let name = ServerName::try_from(DEVICE_HOST).map_err(|_| TunnelError)?;
    Ok(TlsConnector::from(Arc::new(config))
        .connect(name, io)
        .await?)
}

/// 设备侧的内层握手。
#[derive(Clone)]
pub struct DeviceAcceptor(TlsAcceptor);

impl DeviceAcceptor {
    pub fn new(me: &Identity, allow: AllowKey) -> Result<Self> {
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .map_err(|_| TunnelError)?
            .with_client_cert_verifier(Arc::new(PinnedBridges(allow)))
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified(
                me,
            )?)));
        // 不做会话恢复：吊销后必须重新核对公钥
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        Ok(Self(TlsAcceptor::from(Arc::new(config))))
    }

    /// 返回加密流与对方公钥。
    pub async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: S,
    ) -> Result<(server::TlsStream<S>, PublicKey)> {
        let s = self.0.accept(io).await?;
        let key = s
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .and_then(|c| raw_key(c))
            .ok_or(TunnelError)?;
        Ok((s, key))
    }
}

/// 指定的 CA 证书，只允许证书，不允许夹带别的内容。
pub fn parse_ca(pem: &str) -> Result<CertificateDer<'static>> {
    if pem.len() > MAX_CA_PEM || pem.contains("PRIVATE KEY") {
        return Err(TunnelError);
    }
    let cert = CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| TunnelError)?;
    RootCertStore::empty()
        .add(cert.clone())
        .map_err(|_| TunnelError)?;
    Ok(cert)
}

/// 外层 HTTPS。给了 CA 就只认它，否则用内置的公开根证书。
pub(crate) async fn https<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    endpoint: &Endpoint,
    ca: Option<&str>,
) -> Result<client::TlsStream<S>> {
    let mut roots = RootCertStore::empty();
    match ca {
        Some(pem) => roots.add(parse_ca(pem)?).map_err(|_| TunnelError)?,
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13])
        .map_err(|_| TunnelError)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(endpoint.host().to_owned()).map_err(|_| TunnelError)?;
    Ok(TlsConnector::from(Arc::new(config))
        .connect(name, io)
        .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn attempt(
        device: &Identity,
        expect: PublicKey,
        bridge: &Identity,
        allow: PublicKey,
    ) -> bool {
        let (a, b) = tokio::io::duplex(16 * 1024);
        let acceptor = DeviceAcceptor::new(device, Arc::new(move |k| *k == allow)).unwrap();
        let server = async {
            let (mut s, key) = acceptor.accept(b).await?;
            assert_eq!(key, allow);
            s.write_all(b"ok").await?;
            s.shutdown().await?;
            Ok::<_, TunnelError>(())
        };
        let client = async {
            let mut s = bridge_connect(a, bridge, expect).await?;
            let mut got = Vec::new();
            s.read_to_end(&mut got).await?;
            Ok::<_, TunnelError>(got == b"ok")
        };
        let (s, c) = tokio::join!(server, client);
        s.is_ok() && c == Ok(true)
    }

    // AC-NET-06
    #[tokio::test]
    async fn both_sides_accept_only_the_pinned_key() {
        let ids: Vec<_> = (0..3).map(|_| Identity::generate().unwrap()).collect();
        let [device, bridge, other] = &ids[..] else {
            unreachable!()
        };
        let (d, b, o) = (device.public(), bridge.public(), other.public());
        assert!(attempt(device, d, bridge, b).await);
        assert!(!attempt(other, d, bridge, b).await, "冒充设备");
        assert!(!attempt(device, d, other, b).await, "冒充桥接");
        assert!(!attempt(device, o, bridge, b).await);
        assert!(!attempt(device, d, bridge, o).await);
    }

    // 只知道公钥、没有私钥的人不能冒充
    #[tokio::test]
    async fn a_copied_public_key_is_not_enough() {
        let device = Identity::generate().unwrap();
        let thief = Identity::generate().unwrap();
        let bridge = Identity::generate().unwrap();
        let forged = CertifiedKey::new(
            vec![CertificateDer::from([&SPKI[..], &device.public()].concat())],
            ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(thief.pkcs8())).unwrap(),
        );
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(Arc::new(
                forged,
            ))));
        let (a, b) = tokio::io::duplex(16 * 1024);
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (_, r) = tokio::join!(
            async { acceptor.accept(b).await.map(|_| ()) },
            bridge_connect(a, &bridge, device.public())
        );
        assert!(r.is_err());
    }

    #[test]
    fn ca_input_is_checked() {
        assert!(parse_ca("").is_err());
        assert!(parse_ca("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_err());
        assert!(parse_ca(&"x".repeat(MAX_CA_PEM + 1)).is_err());
    }
}
