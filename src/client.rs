use crate::{
    codec::{DataMessageCodec, GnsCodec},
    error::Result,
    messages::DataMessage,
    parser::data_message,
    protos::{
        self, CMsgSteamDatagramCertificateSigned, CMsgSteamNetworkingIdentityLegacyBinary,
        CMsgSteamSocketsUdpConnectOk,
    },
    session::{PeerMode, Session},
};
use bytes::{BufMut, BytesMut};
use log::{info, trace};
use pretty_hex::PrettyHex;
use prost::Message;
use rand_core::{OsRng, RngCore};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio_util::udp::UdpFramed;

pub struct Client {
    session: Session,
    socket: UdpSocket,
    target: SocketAddr,
}

impl Client {
    const MAX_DATAGRAM_SIZE: usize = 65_507;
    const MY_TIMESTAMP: u64 = 3000053608200;
    //const PING_EST_MS: u32 = 100;

    pub async fn connect(target: SocketAddr, steam_id: u64) -> Result<Self> {
        let local_addr: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();
        let socket = UdpSocket::bind(local_addr).await.unwrap();
        // Connection-based UDP doesn't work with tokio UdpFramed
        // https://github.com/tokio-rs/tokio/issues/1506
        //socket.connect(target).await.unwrap();

        // TODO: Key negotiation (4-way handshake)
        let mut challenge_req = protos::CMsgSteamSocketsUdpChallengeRequest::default();
        challenge_req.connection_id = Some(OsRng.next_u32());
        challenge_req.my_timestamp = Some(3000053608200);
        challenge_req.protocol_version = Some(11);
        let mut msg = BytesMut::from([0u8; 512].as_ref());
        let len = challenge_req.encoded_len();
        // ChallengeRequest tag = 0x20
        msg[0] = 0x20;
        [msg[1], msg[2]] = (len as u16).to_le_bytes();
        let mut subset = msg.get_mut(3..len + 3).unwrap();
        challenge_req.encode(&mut subset)?;
        socket.send_to(&msg, target).await?;

        let mut resp = vec![0u8; Self::MAX_DATAGRAM_SIZE];
        let len = socket.recv(&mut resp).await?;
        println!("{:?}", resp[1..len].hex_dump());
        let challenge_reply = protos::CMsgSteamSocketsUdpChallengeReply::decode(&resp[1..len])?;

        let mut connect_req = protos::CMsgSteamSocketsUdpConnectRequest::default();
        connect_req.client_connection_id = challenge_req.connection_id;
        connect_req.challenge = challenge_reply.challenge;
        connect_req.my_timestamp = Some(Self::MY_TIMESTAMP);
        //connect_req.ping_est_ms = Some(Self::PING_EST_MS);
        connect_req.legacy_client_steam_id = Some(steam_id);

        let handshake = Session::handshake();
        let mut info = protos::CMsgSteamDatagramSessionCryptInfo::default();
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

        connect_req.crypt = Some(signed_info);

        let mut cert = protos::CMsgSteamDatagramCertificate::default();
        cert.key_type = Some(protos::c_msg_steam_datagram_certificate::EKeyType::Ed25519 as i32);
        cert.key_data = Some(handshake.public_ed25519_bytes().to_vec());
        cert.legacy_steam_id = Some(steam_id);
        cert.time_created = Some(1646356558);
        cert.time_expiry = Some(1646529358);
        cert.app_ids.push(892970);
        cert.identity_string = Some(format!("steamid:{}", &steam_id));
        let mut legacy_identity_binary = CMsgSteamNetworkingIdentityLegacyBinary::default();
        legacy_identity_binary.steam_id = Some(steam_id);
        cert.legacy_identity_binary = Some(legacy_identity_binary);

        let mut signed_cert = CMsgSteamDatagramCertificateSigned::default();
        signed_cert.cert = Some(cert.encode_to_vec());

        connect_req.cert = Some(signed_cert);

        let mut msg = BytesMut::with_capacity(connect_req.encoded_len() + 1);
        msg.put_u8(0x22);
        msg.put(connect_req.encode_to_vec().as_ref());
        socket.send_to(&msg, target).await?;

        let mut resp = vec![0u8; Self::MAX_DATAGRAM_SIZE];
        let len = socket.recv(&mut resp).await?;
        println!("{:?}", resp[1..len].hex_dump());
        let connect_ok = CMsgSteamSocketsUdpConnectOk::decode(&resp[1..len])?;
        println!("\n\n{:?}\n", &connect_ok);

        let session = handshake.finalize(&connect_req, &connect_ok, PeerMode::Client)?;
        Ok(Self {
            session,
            socket,
            target,
        })
    }

    // pub async fn send(&self, message: DataMessage) -> Result<()> {
    //     todo!()
    // }

    pub async fn recv_one(&mut self) -> Result<DataMessage> {
        let mut resp = [0u8; Self::MAX_DATAGRAM_SIZE];
        let len = self.socket.recv(&mut resp).await?;
        info!("Received Encrypted Data Message? of length {}", len);
        trace!("{:?}", &resp[..len].hex_dump());

        // let sequence_number = u16::from_le_bytes(resp[5..7].try_into().unwrap());
        // if let 0 = &resp[0] ^ 0x80 {
        //     let msg = self.session.decrypt_from_server(&resp[7..len], sequence_number);
        //     trace!("Plaintext: {:?}", &msg.hex_dump());
        //     Ok(Bytes::copy_from_slice(&msg))
        // } else {
        //     Err(crate::Error::UnknownError)
        // }

        let (_, msg) = data_message(&resp[..len]).unwrap();
        //if msg.flags == 0 {
        let plaintext = self
            .session
            .decrypt_from_server(&msg.ciphertext, msg.sequence_number);
        trace!("Plaintext: {:?}", &plaintext.hex_dump());
        //};
        Ok(msg)
    }

    pub fn get_target(&self) -> SocketAddr {
        self.target.to_owned()
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

    pub fn to_gns_framed(self) -> (Session, UdpFramed<GnsCodec>) {
        (self.session, UdpFramed::new(self.socket, GnsCodec))
    }
}
