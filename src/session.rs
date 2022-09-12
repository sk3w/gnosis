use crate::{
    protos::{
        CMsgSteamDatagramSessionCryptInfo, CMsgSteamSocketsUdpConnectOk,
        CMsgSteamSocketsUdpConnectRequest,
    },
    Result,
};
use aes_gcm::{
    aead::{consts::U12, Aead},
    Aes256Gcm, Key, NewAead, Nonce,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ed25519_dalek::{Keypair, Signature, Signer};
use hmac::{Hmac, Mac};
use log::trace;
use pretty_hex::PrettyHex;
use prost::Message;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

type HmacSha256 = Hmac<Sha256>;

pub enum PeerMode {
    Client,
    Server,
}

pub struct Session {
    pub client_connection_id: u32,
    pub server_connection_id: u32,
    peer_mode: PeerMode,
    client_cipher: Aes256Gcm,
    client_nonce: [u8; 12],
    server_cipher: Aes256Gcm,
    server_nonce: [u8; 12],
}

impl Session {
    pub fn handshake() -> Handshake {
        Handshake::new()
    }

    pub fn decrypt(&self, ciphertext: &[u8], sequence_number: u16) -> Bytes {
        match self.peer_mode {
            PeerMode::Client => self.decrypt_from_server(ciphertext, sequence_number),
            PeerMode::Server => self.decrypt_from_client(ciphertext, sequence_number),
        }
    }
    pub fn decrypt_from_client(&self, ciphertext: &[u8], sequence_number: u16) -> Bytes {
        let nonce = self.get_client_nonce(sequence_number);
        trace!("Client nonce for seq num {}: {:x}", sequence_number, &nonce);
        let plaintext = self.client_cipher.decrypt(&nonce, ciphertext).unwrap();
        Bytes::from(plaintext)
    }

    pub fn decrypt_from_server(&self, ciphertext: &[u8], sequence_number: u16) -> Bytes {
        let nonce = self.get_server_nonce(sequence_number);
        trace!("Server nonce for seq num {}: {:x}", sequence_number, &nonce);
        let plaintext = self.server_cipher.decrypt(&nonce, ciphertext).unwrap();
        Bytes::from(plaintext)
    }

    pub fn encrypt(&self, plaintext: Bytes, sequence_number: u16) -> Bytes {
        match self.peer_mode {
            PeerMode::Client => self.encrypt_to_server(plaintext, sequence_number),
            PeerMode::Server => self.encrypt_to_client(plaintext, sequence_number),
        }
    }

    pub fn encrypt_to_client(&self, plaintext: Bytes, sequence_number: u16) -> Bytes {
        let nonce = self.get_server_nonce(sequence_number);
        let ciphertext = self
            .server_cipher
            .encrypt(&nonce, plaintext.as_ref())
            .unwrap();
        Bytes::from(ciphertext)
    }
    pub fn encrypt_to_server(&self, plaintext: Bytes, sequence_number: u16) -> Bytes {
        let nonce = self.get_client_nonce(sequence_number);
        let ciphertext = self
            .client_cipher
            .encrypt(&nonce, plaintext.as_ref())
            .unwrap();
        Bytes::from(ciphertext)
    }

    fn get_client_nonce(&self, sequence_number: u16) -> Nonce<U12> {
        Nonce::from(calculate_nonce(&self.client_nonce, sequence_number))
    }

    fn get_server_nonce(&self, sequence_number: u16) -> Nonce<U12> {
        Nonce::from(calculate_nonce(&self.server_nonce, sequence_number))
    }
}

pub struct Handshake {
    local_secret: EphemeralSecret,
    pub local_nonce: u64,
    local_ed25519: Keypair,
 }

impl Handshake {
    pub fn new() -> Self {
        let local_secret = EphemeralSecret::new(OsRng);
        let mut csprng = OsRng {};
        let local_ed25519 = Keypair::generate(&mut csprng);
        Self {
            local_secret,
            local_nonce: OsRng.next_u64(),
            local_ed25519,
        }
    }

    pub fn public_x25519_bytes(&self) -> [u8; 32] {
        PublicKey::from(&self.local_secret).to_bytes()
    }

    pub fn public_ed25519_bytes(&self) -> [u8; 32] {
        self.local_ed25519.public.to_bytes()
    }

    pub fn sign_proto(&self, message: impl prost::Message) -> Vec<u8> {
        let signature: Signature = self.local_ed25519.sign(&message.encode_to_vec());
        signature.to_bytes().to_vec()
    }

    pub fn finalize(
        self,
        connect_request: &CMsgSteamSocketsUdpConnectRequest,
        connect_ok: &CMsgSteamSocketsUdpConnectOk,
        peer_mode: PeerMode,
    ) -> Result<Session> {
        let signed_crypt_info = match peer_mode {
            PeerMode::Client => connect_ok.crypt.as_ref().unwrap(),
            PeerMode::Server => connect_request.crypt.as_ref().unwrap(),
        };
        let crypt_info_bytes = signed_crypt_info.info.as_ref().unwrap();
        let crypt = CMsgSteamDatagramSessionCryptInfo::decode(crypt_info_bytes.as_slice()).unwrap();
        let remote_x25519_public_key: [u8; 32] = crypt.key_data().try_into().unwrap();
        let remote_x25519_public_key = PublicKey::from(remote_x25519_public_key);
        let remote_nonce = crypt.nonce();

        let shared_secret = self.local_secret.diffie_hellman(&remote_x25519_public_key);
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let premaster_secret = hasher.finalize();
        let premaster_secret = Bytes::copy_from_slice(premaster_secret.as_slice());

        let (client_nonce, server_nonce) = match peer_mode {
            PeerMode::Client => (self.local_nonce, remote_nonce),
            PeerMode::Server => (remote_nonce, self.local_nonce),
        };

        // TODO: struct Salt([u8; 8]) ?
        let mut salt: Vec<u8> = server_nonce.to_le_bytes().to_vec();
        salt.extend(client_nonce.to_le_bytes());
        let salt = Bytes::copy_from_slice(salt.as_slice());

        // TODO: struct Info / Context
        let mut info: Vec<u8> = connect_ok.client_connection_id().to_le_bytes().to_vec();
        info.extend(connect_ok.server_connection_id().to_le_bytes());
        info.extend(b"Steam datagram");
        info.extend(connect_ok.cert.as_ref().unwrap().cert());
        info.extend(connect_request.cert.as_ref().unwrap().cert());
        info.extend(connect_ok.crypt.as_ref().unwrap().info());
        info.extend(connect_request.crypt.as_ref().unwrap().info());
        let info = Bytes::copy_from_slice(info.as_slice());

        let okm = hkdf(128, &premaster_secret, &salt, &info);
        trace!("Client session key: {:?}", &okm.slice(..32).hex_dump());
        let client_key = Key::clone_from_slice(&okm.slice(..32));
        let client_cipher = Aes256Gcm::new(&client_key);
        //let client_nonce = Bytes::copy_from_slice(&okm.slice(64..76));
        trace!("Client session nonce: {:?}", &okm.slice(64..76).hex_dump());
        let client_nonce: [u8; 12] = okm[64..76].try_into().unwrap();
        trace!("Server key: {:?}", &okm.slice(32..64).hex_dump());
        let server_key = Key::clone_from_slice(&okm.slice(32..64));
        let server_cipher = Aes256Gcm::new(&server_key);
        //let server_nonce = Bytes::copy_from_slice(&okm.slice(96..108));
        trace!("Server session nonce: {:?}", &okm.slice(96..108).hex_dump());
        let server_nonce: [u8; 12] = okm[96..108].try_into().unwrap();
        let client_connection_id = connect_ok.client_connection_id();
        let server_connection_id = connect_ok.server_connection_id();

        Ok(Session {
            client_connection_id,
            server_connection_id,
            peer_mode,
            client_cipher,
            client_nonce,
            server_cipher,
            server_nonce,
        })
    }
}

fn hkdf(_length: usize, ikm: &Bytes, salt: &Bytes, info: &Bytes) -> Bytes {
    // Note: ikm is used as the key,
    let prk = HmacSha256::new_from_slice(ikm)
        .unwrap()
        .chain_update(salt)
        .finalize()
        .into_bytes();

    // 4 iterations of "expand" step
    let mut buf = BytesMut::new();
    let mut okm = BytesMut::new();
    for i in 0..4 {
        buf.extend_from_slice(info);
        buf.put_u8((i + 1).into());
        //dbg!(buf.as_ref());
        let mut mac = HmacSha256::new_from_slice(prk.as_slice()).unwrap();
        mac.update(buf.as_ref());
        let out = mac.finalize().into_bytes();
        //dbg!(out);
        okm.extend(out);
        buf = BytesMut::from(out.as_slice());
    }
    okm.freeze()
}

fn calculate_nonce(base_nonce: &[u8; 12], sequence_number: u16) -> [u8; 12] {
    //let mut nonce: [u8; 12] = Default::default();
    let mut nonce: [u8; 12] = base_nonce.clone();
    let mut buf = &nonce[..8];
    let counter = buf.get_u64_le() + (sequence_number as u64);
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hkdf_works() {
        let ikm = hex!(
            "B8 A0 56 D2 8B C0 5B BD  21 A6 CA 11 79 5B 39 85"
            "0C FD AF 81 4D CB 33 5A  F6 6F 3A 22 91 E3 75 FA"
        );
        let ikm = Bytes::copy_from_slice(ikm.as_ref());
        let salt = hex!("18 40 55 E6 5C D7 08 70  75 EC 96 34 B6 BD 19 36");
        let salt = Bytes::copy_from_slice(salt.as_ref());
        let info = hex!(
            "00 8E 97 5B 88 39 84 7C  53 74 65 61 6D 20 64 61"
            "74 61 67 72 61 6D 08 01  12 20 87 75 8B E6 BB 3F"
            "0B 4D 9C 44 ED A8 93 E5  F3 6F 63 34 68 39 E5 8C"
            "2D 11 78 8E 79 C5 F0 AE  6A EC 21 05 F4 C7 67 FC"
            "4F 40 01 45 D7 72 A0 62  4D D7 15 A3 62 50 AA C0"
            "36 5A 0A 81 01 05 F4 C7  67 FC 4F 40 01 62 19 73"
            "74 65 61 6D 69 64 3A 39  30 31 35 39 39 33 38 30"
            "33 38 39 32 30 31 39 37  08 01 12 20 14 BB 6E 82"
            "1D 33 99 94 E3 E4 6B 3B  69 F8 86 D3 AD 47 46 0A"
            "BD D4 76 2F 09 BE 5E AE  C4 90 4E 95 21 27 35 C2"
            "4C 01 00 10 01 45 4E 68  21 62 4D 4E 0B 24 62 50"
            "AA C0 36 62 19 73 74 65  61 6D 69 64 3A 37 36 35"
            "36 31 31 39 39 32 34 38  30 36 31 37 33 35 08 01"
            "12 20 18 AB 50 C8 D8 85  D1 93 E1 F8 62 B2 69 E0"
            "A6 86 D9 E6 3C E0 AC 9A  42 3E 73 49 30 62 7F 91"
            "FB 6D 19 18 40 55 E6 5C  D7 08 70 20 0B 28 02 08"
            "01 12 20 6B 79 25 BF 69  2D E3 90 58 EA 19 98 8D"
            "E0 8A 90 73 98 DE 21 9C  67 32 47 D8 0B 2E 73 2A"
            "63 23 31 19 75 EC 96 34  B6 BD 19 36 20 0B 28 02"
        );
        let info = Bytes::copy_from_slice(info.as_ref());
        let expected_okm = hex!(
            "D5 B3 18 1C A3 68 C0 4D  7F 1F FD EC B2 6C 00 C2"
            "61 AE C3 FF 96 E3 D9 9D  B9 F3 AE 71 A5 33 25 4F"
            "0C EB FA FF 59 58 3E BD  DE E3 0B 64 49 A9 85 C4"
            "BF 8A 56 54 EC 6D 51 03  C5 D3 C4 2E 5F DD 3B FC"
            "BE 14 54 D6 9C C1 E0 AC  72 0B 98 A3 5E 7D AE E1"
            "D8 71 19 5B 95 D9 B1 DB  23 F2 2E A6 D0 39 F2 1C"
            "4A 56 F5 9A 8C E3 80 27  67 D5 43 77 45 68 FB 56"
            "87 E2 80 DA E6 85 A0 26  04 4A A8 E1 A2 51 23 9E"
        );
        let expected_okm = Bytes::copy_from_slice(expected_okm.as_ref());
        let okm = hkdf(128, &ikm, &salt, &info);
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn calculate_nonce_works() {
        let base_nonce = &hex!("00 01 02 03 04 05 06 07  08 09 0A 0B");
        let sequence_number: u16 = 0x101;
        assert_eq!(
            calculate_nonce(base_nonce, sequence_number),
            hex!("01 02 02 03 04 05 06 07  08 09 0A 0B"),
        )
    }
}
