use std::{net::SocketAddr, sync::Arc};

use futures::{stream::StreamExt, SinkExt};
use tokio::sync::Mutex;

use crate::{BasicServer, Client, Result};

pub struct Proxy {
    client: Client,
    server: BasicServer,
    stats: Arc<Mutex<ProxyStats>>,
}

impl Proxy {
    pub async fn new(
        listen_addr: SocketAddr,
        upstream_addr: SocketAddr,
        client_steam_id: u64,
        server_steam_id: u64,
    ) -> Result<Self> {
        let server = BasicServer::listen(listen_addr, server_steam_id).await?;
        let client = Client::connect(upstream_addr, client_steam_id).await?;
        dbg!(&client.get_client_connection_id());
        dbg!(&client.get_server_connection_id());
        let stats = Arc::new(Mutex::new(ProxyStats::new()));
        Ok(Self {
            client,
            server,
            stats,
        })
    }

    pub async fn run(self) -> Result<()> {
        let target = self.client.get_target();
        let client_addr = self.server.get_client_addr();
        let down_client_connection_id = self.server.get_client_connection_id();
        let up_server_connection_id = self.client.get_server_connection_id();
        let (mut down_write, mut down_read) = self.server.to_framed().split();
        let (mut up_write, mut up_read) = self.client.to_framed().split();
        let stats = Arc::clone(&self.stats);
        let downstream = tokio::spawn(async move {
            // Receive messages from client
            while let Some(res) = down_read.next().await {
                match res {
                    Ok((mut msg, _)) => {
                        msg.flags = 0;
                        msg.to_connection_id = up_server_connection_id;
                        up_write.send((msg, target)).await.unwrap();
                        stats.lock().await.inc_up();
                    }
                    Err(_) => (), // TODO: Handle codec errors
                }
            }
        });
        let stats = Arc::clone(&self.stats);
        let upstream = tokio::spawn(async move {
            // Receive messages from server
            while let Some(res) = up_read.next().await {
                match res {
                    Ok((mut msg, _)) => {
                        msg.flags = 0;
                        msg.to_connection_id = down_client_connection_id;
                        down_write.send((msg, client_addr)).await.unwrap();
                        stats.lock().await.inc_down();
                    }
                    Err(_) => (), // TODO: Handle codec errors
                }
            }
        });
        let (_down_res, _up_res) = (downstream.await.unwrap(), upstream.await.unwrap());
        Ok(())
    }

    pub fn get_stats(&self) -> Arc<Mutex<ProxyStats>> {
        Arc::clone(&self.stats)
    }
}

pub struct ProxyStats {
    /// Number of messages passed from upstream server to downstream client
    passed_downstream: usize,
    /// Number of messages passed from downstream client to upstream server
    passed_upstream: usize,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            passed_downstream: 0,
            passed_upstream: 0,
        }
    }

    fn inc_down(&mut self) {
        self.passed_downstream += 1;
    }

    fn inc_up(&mut self) {
        self.passed_upstream += 1;
    }
}

fn search(needle: &[u8], haystack: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::search;

    #[test]
    fn search_works() {
        let haystack = Bytes::from_static(b"abcdefg12345");
        let needle = b"efg1";
        assert_eq!(search(needle, &haystack), Some(4))
    }
}
