//! A libp2p transport that resolves `/dns`, `/dns4` and `/dns6` addresses with
//! the operating system's resolver (getaddrinfo, through tokio) instead of
//! hickory.
//!
//! Used on Windows: hickory sends its queries from its own UDP sockets bound to
//! 0.0.0.0, and Windows Defender Firewall then asks the user whether the
//! program may accept incoming connections, although it never listens.

use std::fmt;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};

use futures::future::{BoxFuture, MapErr};
use futures::{FutureExt, TryFutureExt};
use libp2p::core::multiaddr::Protocol;
use libp2p::core::transport::{ListenerId, TransportError, TransportEvent};
use libp2p::{Multiaddr, Transport};

#[derive(Debug)]
pub enum Error<E> {
    Transport(E),
    Resolve(std::io::Error),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "{e}"),
            Error::Resolve(e) => write!(f, "DNS resolution failed: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport(e) => Some(e),
            Error::Resolve(e) => Some(e),
        }
    }
}

pub struct SystemDnsTransport<T> {
    inner: Arc<Mutex<T>>,
}

impl<T> SystemDnsTransport<T> {
    pub fn new(inner: T) -> Self {
        Self { inner: Arc::new(Mutex::new(inner)) }
    }
}

fn lock<T>(inner: &Mutex<T>) -> MutexGuard<'_, T> {
    inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The host name and the IP versions it may resolve to, when `addr` starts
/// with a DNS name followed by TCP. Anything else goes to the inner transport
/// unchanged.
fn dns_host(addr: &Multiaddr) -> Option<(String, bool, bool)> {
    let mut iter = addr.iter();
    let host = match iter.next()? {
        Protocol::Dns(h) => (h.to_string(), true, true),
        Protocol::Dns4(h) => (h.to_string(), true, false),
        Protocol::Dns6(h) => (h.to_string(), false, true),
        _ => return None,
    };
    matches!(iter.next(), Some(Protocol::Tcp(_))).then_some(host)
}

impl<T> SystemDnsTransport<T>
where
    T: Transport + Send + 'static,
    T::Dial: Send,
    T::Error: Send,
    T::Output: Send,
{
    fn do_dial(
        &mut self,
        addr: Multiaddr,
        as_listener: bool,
    ) -> Result<BoxFuture<'static, Result<T::Output, Error<T::Error>>>, TransportError<Error<T::Error>>>
    {
        let Some((host, v4, v6)) = dns_host(&addr) else {
            let mut inner = lock(&self.inner);
            let dial = if as_listener { inner.dial_as_listener(addr) } else { inner.dial(addr) };
            return dial
                .map(|fut| fut.map_err(Error::Transport).boxed())
                .map_err(|e| e.map(Error::Transport));
        };

        let inner = Arc::clone(&self.inner);
        let rest: Multiaddr = addr.iter().skip(1).collect();
        Ok(async move {
            let ips: Vec<IpAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(Error::Resolve)?
                .map(|sa| sa.ip())
                .filter(|ip| (ip.is_ipv4() && v4) || (ip.is_ipv6() && v6))
                .collect();

            let mut last_error = Error::Resolve(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no address found for {host}"),
            ));
            for ip in ips {
                let mut resolved = Multiaddr::empty().with(match ip {
                    IpAddr::V4(ip) => Protocol::Ip4(ip),
                    IpAddr::V6(ip) => Protocol::Ip6(ip),
                });
                for protocol in rest.iter() {
                    resolved.push(protocol);
                }
                let dial = {
                    let mut inner = lock(&inner);
                    if as_listener { inner.dial_as_listener(resolved) } else { inner.dial(resolved) }
                };
                match dial {
                    Ok(fut) => match fut.await {
                        Ok(output) => return Ok(output),
                        Err(e) => last_error = Error::Transport(e),
                    },
                    Err(TransportError::Other(e)) => last_error = Error::Transport(e),
                    Err(TransportError::MultiaddrNotSupported(a)) => {
                        last_error = Error::Resolve(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            format!("address not supported: {a}"),
                        ))
                    }
                }
            }
            Err(last_error)
        }
        .boxed())
    }
}

impl<T> Transport for SystemDnsTransport<T>
where
    T: Transport + Send + Unpin + 'static,
    T::Dial: Send,
    T::Error: Send,
    T::Output: Send,
{
    type Output = T::Output;
    type Error = Error<T::Error>;
    type ListenerUpgrade = MapErr<T::ListenerUpgrade, fn(T::Error) -> Self::Error>;
    type Dial = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn listen_on(
        &mut self,
        id: ListenerId,
        addr: Multiaddr,
    ) -> Result<(), TransportError<Self::Error>> {
        lock(&self.inner).listen_on(id, addr).map_err(|e| e.map(Error::Transport))
    }

    fn remove_listener(&mut self, id: ListenerId) -> bool {
        lock(&self.inner).remove_listener(id)
    }

    fn dial(&mut self, addr: Multiaddr) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.do_dial(addr, false)
    }

    fn dial_as_listener(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Self::Dial, TransportError<Self::Error>> {
        self.do_dial(addr, true)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<TransportEvent<Self::ListenerUpgrade, Self::Error>> {
        let mut inner = lock(&self.inner);
        Transport::poll(Pin::new(&mut *inner), cx).map(|event| {
            event
                .map_upgrade(|upgrade| upgrade.map_err(Error::Transport as fn(_) -> _))
                .map_err(Error::Transport)
        })
    }

    fn address_translation(&self, listen: &Multiaddr, observed: &Multiaddr) -> Option<Multiaddr> {
        lock(&self.inner).address_translation(listen, observed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use libp2p::tcp;

    #[tokio::test]
    async fn dials_a_dns_name_through_the_system_resolver() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut socket, b"biscuit").await.unwrap();
        });

        let mut transport = SystemDnsTransport::new(tcp::tokio::Transport::new(tcp::Config::new()));
        let addr: Multiaddr = format!("/dns4/localhost/tcp/{port}").parse().unwrap();
        let mut stream = transport.dial(addr).unwrap().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"biscuit");
        stream.close().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn leaves_other_addresses_to_the_inner_transport() {
        assert!(dns_host(&"/ip4/127.0.0.1/tcp/1".parse().unwrap()).is_none());
        assert!(dns_host(&"/dnsaddr/example.org".parse().unwrap()).is_none());
        assert_eq!(
            dns_host(&"/dns4/example.org/tcp/443/wss".parse().unwrap()),
            Some(("example.org".to_string(), true, false))
        );
    }
}
