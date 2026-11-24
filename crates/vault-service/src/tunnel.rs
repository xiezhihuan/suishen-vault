//! 公网档：主动连到跳板，断线按退避重连。连接全部由监听任务持有，关闭服务即全部丢弃。
use crate::http::{Session, Via, serve};
use crate::remote::Remote;
use serde::Serialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
    time::timeout,
};
use vault_tunnel::{
    DEVICE_PATH, DEVICE_PROTOCOL, HANDSHAKE_TIMEOUT, PING_TIMEOUT, STREAM_BRIDGE, STREAM_CONTROL,
    STREAM_DIRECT, SUPERSEDED,
    dial::{self, Connection},
    handshake::{self, Verdict},
    mux::{self, MAX_STREAMS, Stream},
    tls::DeviceAcceptor,
};

const MAX_DELAY: Duration = Duration::from_secs(60);
/// 在线超过这么久才算稳定，重连退避归零。
const STABLE: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    /// 没有开放公网。
    #[default]
    Off,
    Connecting,
    Online,
    /// 连不上，正在等待重连。
    Offline,
    /// 跳板不认这台设备。
    Rejected,
    /// 已被新设备取代，服务随之关闭。
    Superseded,
}

enum End {
    Lost,
    Rejected,
    Superseded,
}

pub(crate) async fn run(session: Arc<Session>, remote: Remote, direct: bool) {
    let allow = {
        let session = session.clone();
        Arc::new(move |key: &_| {
            session
                .with(|e| Ok(e.knows_bridge(key)))
                .is_ok_and(|known| known)
        })
    };
    let Ok(acceptor) = DeviceAcceptor::new(&remote.device, allow) else {
        session.set_tunnel(TunnelState::Offline);
        return;
    };
    let mut delay = Duration::from_secs(1);
    loop {
        session.set_tunnel(TunnelState::Connecting);
        let started = Instant::now();
        let end = match connect(&remote, direct).await {
            Ok(io) => {
                session.set_tunnel(TunnelState::Online);
                online(&session, &remote, &acceptor, direct, io).await
            }
            Err(end) => end,
        };
        match end {
            End::Superseded => {
                let _ = session.with(|e| e.relay_superseded());
                // 先关服务再改状态，不让界面看到"已被取代却还开着"
                session.close();
                session.set_tunnel(TunnelState::Superseded);
                return;
            }
            End::Rejected => {
                session.set_tunnel(TunnelState::Rejected);
                delay = MAX_DELAY;
            }
            End::Lost => {
                session.set_tunnel(TunnelState::Offline);
                if started.elapsed() > STABLE {
                    delay = Duration::from_secs(1);
                }
            }
        }
        tokio::time::sleep(jittered(delay)).await;
        delay = (delay * 2).min(MAX_DELAY);
    }
}

/// 在 75% 到 125% 之间。
fn jittered(d: Duration) -> Duration {
    let r = vault_tunnel::random::<1>().map_or(128, |b| u32::from(b[0]));
    d * (192 + r / 2) / 256
}

async fn connect(remote: &Remote, direct: bool) -> Result<Connection, End> {
    let mut io = dial::upgrade(
        &remote.endpoint,
        remote.ca.as_deref(),
        DEVICE_PATH,
        DEVICE_PROTOCOL,
    )
    .await
    .ok()
    .flatten()
    .ok_or(End::Lost)?;
    match handshake::prove(
        &mut io,
        &remote.endpoint.authority(),
        &remote.relay,
        None,
        direct,
    )
    .await
    {
        Ok(Verdict::Accepted) => Ok(io),
        Ok(Verdict::Rejected) => Err(End::Rejected),
        Ok(Verdict::Superseded) => Err(End::Superseded),
        Err(_) => Err(End::Lost),
    }
}

async fn online(
    session: &Arc<Session>,
    remote: &Remote,
    acceptor: &DeviceAcceptor,
    direct: bool,
    io: Connection,
) -> End {
    let (mut incoming, drive) = mux::acceptor(io);
    tokio::pin!(drive);
    let (beat, mut beats) = tokio::sync::mpsc::channel(8);
    let line = Line {
        session: session.clone(),
        acceptor: acceptor.clone(),
        host: remote.endpoint.authority().into(),
        direct,
        beat,
    };
    // 局部变量：本次连接结束时，所有流随之中断
    let mut streams = JoinSet::new();
    let deadline = tokio::time::sleep(PING_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            () = &mut drive => return End::Lost,
            () = &mut deadline => return End::Lost,
            Some(byte) = beats.recv() => match byte {
                SUPERSEDED => return End::Superseded,
                _ => deadline.as_mut().reset(tokio::time::Instant::now() + PING_TIMEOUT),
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
            Some(s) = incoming.recv() => {
                if streams.len() < MAX_STREAMS {
                    streams.spawn(line.clone().stream(s));
                }
            }
        }
    }
}

#[derive(Clone)]
struct Line {
    session: Arc<Session>,
    acceptor: DeviceAcceptor,
    host: Arc<str>,
    direct: bool,
    beat: tokio::sync::mpsc::Sender<u8>,
}

impl Line {
    async fn stream(self, mut s: Stream) {
        let mut kind = [0];
        if !matches!(
            timeout(HANDSHAKE_TIMEOUT, s.read_exact(&mut kind)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        match kind[0] {
            STREAM_CONTROL => self.control(s).await,
            // 跳板不可信：即使它转来直连请求，这里仍按用户的选择拒绝
            STREAM_DIRECT if self.direct => {
                serve(s, self.session, Via::Direct(self.host)).await;
            }
            STREAM_BRIDGE => {
                if let Ok(Ok((tls, peer))) =
                    timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(s)).await
                {
                    serve(tls, self.session, Via::Bridge(peer)).await;
                }
            }
            _ => {}
        }
    }

    /// 回送心跳，并把收到的字节报给主循环。
    async fn control(self, mut s: Stream) {
        let mut byte = [0];
        while s.read_exact(&mut byte).await.is_ok() {
            if self.beat.send(byte[0]).await.is_err()
                || s.write_all(&byte).await.is_err()
                || s.flush().await.is_err()
            {
                return;
            }
        }
    }
}
