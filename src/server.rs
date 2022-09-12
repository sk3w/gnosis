use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use bytes::{BufMut, BytesMut};
use futures::{
    stream::{SplitSink, SplitStream},
    Future, SinkExt, Stream, StreamExt,
};
use log::{error, trace};
use pretty_hex::PrettyHex;
use prost::Message;
use tokio::{net::UdpSocket, sync::Mutex};
use tokio_util::udp::UdpFramed;

use crate::{
    codec::{DataMessageCodec, GnsCodec},
    messages::{DataMessage, DataMessageP, GnsFrame},
    parser,
    protos::{
        self, CMsgSteamDatagramCertificate, CMsgSteamDatagramCertificateSigned,
        CMsgSteamDatagramSessionCryptInfo, CMsgSteamNetworkingIdentityLegacyBinary,
        CMsgSteamSocketsUdpChallengeReply, CMsgSteamSocketsUdpChallengeRequest,
        CMsgSteamSocketsUdpConnectOk, CMsgSteamSocketsUdpConnectRequest,
    },
    session::{Handshake, PeerMode, Session},
};

type Outbound = Arc<Mutex<SplitSink<UdpFramed<GnsCodec>, (GnsFrame, SocketAddr)>>>;

/// A Handler is a consumer-provided value to receive and handle incoming DataMessage values from a
/// connected client
pub trait Handler<Fut>: Clone
where
    Fut: Future<Output = ()> + Send + 'static,
{
    fn run(
        self,
        client_addr: SocketAddr,
        receiver: impl Stream<Item = DataMessageP>,
        sender: Outbound,
    ) -> Fut;
}

pub struct Server {
    // TODO: key to (SocketAddr, u32) including client connection id
    dispatch: HashMap<SocketAddr, flume::Sender<DataMessage>>,
    inbound: SplitStream<UdpFramed<GnsCodec, UdpSocket>>,
    outbound: Outbound,
    steam_id: u64,
}

impl Server {
    const CHANNEL_CAPACITY: usize = 16;
    const MAX_CLIENTS: usize = 2;

    pub async fn listen(addr: SocketAddr, steam_id: u64) -> Result<Self, io::Error> {
        let dispatch: HashMap<SocketAddr, flume::Sender<DataMessage>> = HashMap::new();
        let socket = UdpSocket::bind(&addr).await?;
        let framed = UdpFramed::new(socket, GnsCodec {});
        let (outbound, inbound) = framed.split();
        let outbound = Arc::new(Mutex::new(outbound));
        Ok(Self {
            dispatch,
            inbound,
            outbound,
            steam_id,
        })
    }

    // pub async fn run<H, F>(&mut self, handler: H) -> Result<(), crate::error::Error>
    // where
    //     H: Copy + Send + Sync + 'static,
    //     H: Fn(&Outbound, DataMessage, &SocketAddr) -> F,
    //     F: Future<Output = ()> + Send + 'static,
    pub async fn run<H, Fut>(&mut self, handler: H) -> Result<(), crate::error::Error>
    where
        H: Handler<Fut>,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // while let Some(Ok((frame, addr))) = self.framed.next().await {
        for _ in 0..12 {
            match self.inbound.next().await {
                Some(Ok((frame, addr))) => {
                    trace!("Listener received a frame from {addr}: {frame:?}");
                    match frame {
                        GnsFrame::ChallengeRequest(msg) => {
                            self.send_challenge_reply(msg, addr).await?
                        }
                        GnsFrame::ChallengeReply(_) => (), // Ignore
                        GnsFrame::ConnectRequest(msg) => {
                            // Dispatch a handler or ignore if MAX_CLIENTS is hit
                            if self.dispatch.contains_key(&addr) {
                                // Ignore?
                            } else if self.dispatch.len() >= Self::MAX_CLIENTS {
                                // Ignore?
                            } else {
                                self.spawn_handler(msg, addr, handler.clone()).await?
                            }
                        }
                        GnsFrame::ConnectOk(_) => (), // Ignore
                        GnsFrame::ConnectionClosed(_) => todo!(), // Dispatch to handler or ignore
                        GnsFrame::NoConnection(_) => (), // Ignore
                        GnsFrame::Data(msg) => {
                            // Dispatch to appropriate handler via flume tx
                            let tx = self.dispatch.get(&addr).unwrap();
                            tx.send_async(msg).await.unwrap();
                        }
                    }
                }
                Some(Err(e)) => error!("Error: {e:#?}"),
                None => error!("Received None!"),
            };
        }
        Ok(())
    }

    async fn send_challenge_reply(
        &mut self,
        msg: CMsgSteamSocketsUdpChallengeRequest,
        addr: SocketAddr,
    ) -> Result<(), crate::error::Error> {
        let mut reply = CMsgSteamSocketsUdpChallengeReply::default();
        reply.connection_id = msg.connection_id;
        reply.challenge = Some(0);
        reply.your_timestamp = msg.my_timestamp;
        reply.protocol_version = msg.protocol_version;
        trace!("Sending a challenge reply: {reply:?}");
        self.outbound
            .lock()
            .await
            .send((reply.into(), addr))
            .await?;
        Ok(())
    }

    async fn spawn_handler<H, Fut>(
        &mut self,
        connect_request: CMsgSteamSocketsUdpConnectRequest,
        client_addr: SocketAddr,
        handler: H,
    ) -> Result<(), crate::error::Error>
    where
        H: Handler<Fut>,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handshake = Session::handshake();
        let connect_ok =
            build_connect_ok_message(&handshake, &connect_request, self.steam_id);
        let mut session = handshake.finalize(&connect_request, &connect_ok, PeerMode::Server)?;
        let (tx, rx) = flume::bounded(Self::CHANNEL_CAPACITY);
        let outbound: Arc<Mutex<SplitSink<UdpFramed<GnsCodec>, (GnsFrame, SocketAddr)>>> =
            Arc::clone(&self.outbound);

        // New handler task
        // TODO: Implement a timeout
        // tokio::spawn(async move {
        //     let addr = addr.to_owned();
        //     loop {
        //         let msg = rx.recv_async().await.unwrap();
        //         handler(&outbound, msg, &addr).await;
        //     }
        // });

        // New handler task - alternate way
        //tokio::spawn(ServerTask::new(client_addr.to_owned(), handler, rx, outbound, session).run());

        let receiver = rx.into_stream().map(|msg: DataMessage| msg.decrypt(&mut session));
        tokio::spawn(handler.run(client_addr, receiver, outbound));

        self.dispatch.insert(client_addr, tx);
        // TODO: track tasks? so we can update self.dispatch if they complete?
        self.outbound
            .lock()
            .await
            .send((connect_ok.into(), client_addr))
            .await?;
        //todo!()
        Ok(())
    }
}

fn build_connect_ok_message(
    handshake: &Handshake,
    connect_request: &CMsgSteamSocketsUdpConnectRequest,
    server_steam_id: u64,
) -> CMsgSteamSocketsUdpConnectOk {
    let mut connect_ok = CMsgSteamSocketsUdpConnectOk::default();
    connect_ok.client_connection_id = connect_request.client_connection_id;
    // TODO: generate a real connection ID
    connect_ok.server_connection_id = Some(1);
    connect_ok.your_timestamp = connect_request.my_timestamp;
    // TODO: calculate actual delay time?
    connect_ok.delay_time_usec = Some(1000);
    connect_ok.legacy_server_steam_id = Some(server_steam_id);

    let mut info = CMsgSteamDatagramSessionCryptInfo::default();
    info.key_type =
        Some(protos::c_msg_steam_datagram_session_crypt_info::EKeyType::Curve25519 as i32);
    info.key_data = Some(handshake.public_x25519_bytes().to_vec());
    info.nonce = Some(handshake.local_nonce);
    info.protocol_version = Some(11);
    info.push_ciphers(
        protos::ESteamNetworkingSocketsCipher::KESteamNetworkingSocketsCipherAes256Gcm,
    );
    let mut signed_info = protos::CMsgSteamDatagramSessionCryptInfoSigned::default();
    signed_info.info = Some(info.encode_to_vec());
    signed_info.signature = Some(handshake.sign_proto(info));
    connect_ok.crypt = Some(signed_info);

    let mut cert = CMsgSteamDatagramCertificate::default();
    cert.key_type = Some(protos::c_msg_steam_datagram_certificate::EKeyType::Ed25519 as i32);
    cert.key_data = Some(handshake.public_ed25519_bytes().to_vec());
    cert.legacy_steam_id = Some(server_steam_id);
    cert.time_created = Some(1646356558);
    cert.time_expiry = Some(1646529358);
    cert.app_ids.push(892970);
    cert.identity_string = Some(format!("steamid:{}", server_steam_id));
    let mut legacy_identity_binary = CMsgSteamNetworkingIdentityLegacyBinary::default();
    legacy_identity_binary.steam_id = Some(server_steam_id);
    cert.legacy_identity_binary = Some(legacy_identity_binary);

    let mut signed_cert = CMsgSteamDatagramCertificateSigned::default();
    signed_cert.cert = Some(cert.encode_to_vec());
    connect_ok.cert = Some(signed_cert);
    connect_ok
}

pub struct BasicServer {
    session: Session,
    socket: UdpSocket,
    steam_id: u64,
    client_addr: SocketAddr,
}

impl BasicServer {
    const MAX_DATAGRAM_SIZE: usize = 65_507;

    pub async fn listen(addr: SocketAddr, steam_id: u64) -> Result<Self, io::Error> {
        let socket = UdpSocket::bind(&addr).await?;
        let handshake = Session::handshake();

        let mut buf = [0u8; Self::MAX_DATAGRAM_SIZE];
        let (len, client_addr) = socket.recv_from(&mut buf).await?;
        let (_, msg) = parser::challenge_request(&buf[..len]).unwrap();
        println!("Received:\n{:?}", &buf[..len].hex_dump());
        println!("Msg: {:?}", &msg);

        let mut reply = CMsgSteamSocketsUdpChallengeReply::default();
        reply.connection_id = msg.connection_id;
        reply.challenge = Some(0);
        reply.your_timestamp = msg.my_timestamp;
        reply.protocol_version = msg.protocol_version;

        let mut send_buf = BytesMut::with_capacity(1 + reply.encoded_len());
        send_buf.put_u8(0x21);
        send_buf.put(reply.encode_to_vec().as_ref());
        socket.send_to(&send_buf, client_addr).await?;

        // Receive ConnectRequest
        let len = socket.recv(&mut buf).await?;
        let (_, connect_request) = parser::connect_request(&buf[..len]).unwrap();
        println!("Received:\n{:?}", &buf[..len].hex_dump());
        println!("Msg: {:?}", &connect_request);

        let (session, connect_ok) = Self::recv_connect_request(handshake, connect_request, steam_id).unwrap();

        let mut send_buf = BytesMut::with_capacity(1 + connect_ok.encoded_len());
        send_buf.put_u8(0x23);
        connect_ok.encode(&mut send_buf)?;
        socket.send_to(&send_buf, client_addr).await?;

        Ok(Self {
            session,
            socket,
            steam_id,
            client_addr,
        })
    }

    fn recv_connect_request(
        handshake: Handshake,
        connect_request: CMsgSteamSocketsUdpConnectRequest,
        server_steam_id: u64,
    ) -> crate::Result<(Session, CMsgSteamSocketsUdpConnectOk)> {
        let mut connect_ok = CMsgSteamSocketsUdpConnectOk::default();
        connect_ok.client_connection_id = connect_request.client_connection_id;
        // TODO: generate a real connection ID
        connect_ok.server_connection_id = Some(1);
        connect_ok.your_timestamp = connect_request.my_timestamp;
        // TODO: calculate actual delay time?
        connect_ok.delay_time_usec = Some(1000);
        connect_ok.legacy_server_steam_id = Some(server_steam_id);

        let mut info = CMsgSteamDatagramSessionCryptInfo::default();
        info.key_type =
            Some(protos::c_msg_steam_datagram_session_crypt_info::EKeyType::Curve25519 as i32);
        info.key_data = Some(handshake.public_x25519_bytes().to_vec());
        info.nonce = Some(handshake.local_nonce);
        info.protocol_version = Some(11);
        info.push_ciphers(
            protos::ESteamNetworkingSocketsCipher::KESteamNetworkingSocketsCipherAes256Gcm,
        );
        let mut signed_info = protos::CMsgSteamDatagramSessionCryptInfoSigned::default();
        signed_info.info = Some(info.encode_to_vec());
        signed_info.signature = Some(handshake.sign_proto(info));
        connect_ok.crypt = Some(signed_info);

        let mut cert = CMsgSteamDatagramCertificate::default();
        cert.key_type = Some(protos::c_msg_steam_datagram_certificate::EKeyType::Ed25519 as i32);
        cert.key_data = Some(handshake.public_ed25519_bytes().to_vec());
        cert.legacy_steam_id = Some(server_steam_id);
        cert.time_created = Some(1646356558);
        cert.time_expiry = Some(1646529358);
        cert.app_ids.push(892970);
        cert.identity_string = Some(format!("steamid:{}", server_steam_id));
        let mut legacy_identity_binary = CMsgSteamNetworkingIdentityLegacyBinary::default();
        legacy_identity_binary.steam_id = Some(server_steam_id);
        cert.legacy_identity_binary = Some(legacy_identity_binary);

        let mut signed_cert = CMsgSteamDatagramCertificateSigned::default();
        signed_cert.cert = Some(cert.encode_to_vec());

        connect_ok.cert = Some(signed_cert);

        let session = handshake.finalize(&connect_request, &connect_ok, PeerMode::Server)?;
        Ok((session, connect_ok))
    }

    pub fn get_client_addr(&self) -> SocketAddr {
        self.client_addr.to_owned()
    }

    pub fn get_client_connection_id(&self) -> u32 {
        self.session.client_connection_id
    }

    pub fn get_server_connection_id(&self) -> u32 {
        self.session.server_connection_id
    }

    pub fn to_framed(self) -> UdpFramed<DataMessageCodec> {
        UdpFramed::new(self.socket, DataMessageCodec::new(self.session))
    }
}
