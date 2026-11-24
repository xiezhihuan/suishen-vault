//! yamux 多路复用的驱动。每条流是一个普通的 tokio 双向字节流。
use crate::{Result, TunnelError};
use std::task::Poll;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

pub type Stream = Compat<yamux::Stream>;

/// 单条隧道同时存在的流。
pub const MAX_STREAMS: usize = 64;

fn config() -> yamux::Config {
    let mut c = yamux::Config::default();
    c.set_max_num_streams(MAX_STREAMS);
    c.set_max_connection_receive_window(Some(MAX_STREAMS * 256 * 1024));
    c
}

#[derive(Clone)]
pub struct Opener(mpsc::Sender<oneshot::Sender<Stream>>);

impl Opener {
    pub async fn open(&self) -> Result<Stream> {
        let (tx, rx) = oneshot::channel();
        self.0.send(tx).await.map_err(|_| TunnelError)?;
        rx.await.map_err(|_| TunnelError)
    }
}

/// 跳板侧。返回的 future 须一直运行，结束即隧道断开，丢弃即断开隧道。
pub fn opener<S>(io: S) -> (Opener, impl Future<Output = ()> + Send)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<oneshot::Sender<Stream>>(MAX_STREAMS);
    let mut conn = yamux::Connection::new(io.compat(), config(), yamux::Mode::Client);
    let drive = async move {
        let mut waiting: Option<oneshot::Sender<Stream>> = None;
        std::future::poll_fn(move |cx| {
            loop {
                if waiting.is_none()
                    && let Poll::Ready(Some(req)) = rx.poll_recv(cx)
                {
                    waiting = Some(req);
                }
                if waiting.is_some() {
                    match conn.poll_new_outbound(cx) {
                        Poll::Ready(Ok(s)) => {
                            if let Some(tx) = waiting.take() {
                                let _ = tx.send(s.compat());
                            }
                            continue;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                // 设备不应主动开流，多出来的直接丢弃
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(_))) => {}
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    };
    (Opener(tx), drive)
}

/// 设备侧。流经通道交出，future 的用法同上。
pub fn acceptor<S>(io: S) -> (mpsc::Receiver<Stream>, impl Future<Output = ()> + Send)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel(MAX_STREAMS);
    let mut conn = yamux::Connection::new(io.compat(), config(), yamux::Mode::Server);
    let drive = async move {
        std::future::poll_fn(move |cx| {
            loop {
                match conn.poll_next_inbound(cx) {
                    // 通道满即丢弃新流，不阻塞已有的流
                    Poll::Ready(Some(Ok(s))) => drop(tx.try_send(s.compat())),
                    Poll::Ready(_) => return Poll::Ready(()),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
    };
    (rx, drive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn many_streams_share_one_connection_and_end_together() {
        let (a, b) = tokio::io::duplex(4096);
        let (open, relay) = opener(a);
        let (mut incoming, device) = acceptor(b);
        let relay = tokio::spawn(relay);
        let device = tokio::spawn(device);
        tokio::spawn(async move {
            while let Some(mut s) = incoming.recv().await {
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    s.read_to_end(&mut data).await.unwrap();
                    data.reverse();
                    s.write_all(&data).await.unwrap();
                    s.shutdown().await.unwrap();
                });
            }
        });
        let mut jobs = tokio::task::JoinSet::new();
        for i in 0..40u8 {
            let open = open.clone();
            jobs.spawn(async move {
                let mut s = open.open().await.unwrap();
                let mut data = vec![i; 100_000];
                data[0] = 255;
                s.write_all(&data).await.unwrap();
                s.shutdown().await.unwrap();
                let mut back = Vec::new();
                s.read_to_end(&mut back).await.unwrap();
                data.reverse();
                assert!(back == data);
            });
        }
        while let Some(r) = jobs.join_next().await {
            r.unwrap();
        }
        device.abort();
        tokio::time::timeout(std::time::Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        assert!(open.open().await.is_err());
    }
}
