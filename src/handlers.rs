#[allow(dead_code)]
#[derive(Debug)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
}

#[derive(Debug, serde::Serialize)]
pub struct Response {
    pub data: String,
    pub error: Option<&'static str>,
}

pub fn parse_apdu(bytes: &[u8]) -> Result<Apdu<'_>, &'static str> {
    if bytes.len() < 5 {
        return Err("APDU is shorter than its five-byte header");
    }
    let data_len = bytes[4] as usize;
    if bytes.len() != 5 + data_len {
        return Err("APDU length does not match its header");
    }
    Ok(Apdu {
        cla: bytes[0],
        ins: bytes[1],
        p1: bytes[2],
        p2: bytes[3],
        data: &bytes[5..],
    })
}

pub fn handle(
    apdu: &Apdu<'_>,
    response_data: &str,
    seed_phrase: Option<&str>,
    account_index: u32,
    network: crate::Network,
) -> Response {
    const CLA_ZCASH: u8 = 0xE0;
    const INS_GET_VK: u8 = 0x50;
    const INS_GET_ADDRESS: u8 = 0x51;
    const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;
    if apdu.cla != CLA_ZCASH {
        return canned(response_data);
    }
    match apdu.ins {
        INS_GET_VK => get_viewing_key(seed_phrase, account_index, network),
        INS_GET_ADDRESS => get_address(seed_phrase, account_index, network),
        INS_GET_FIRMWARE_VERSION => firmware_version(),
        _ => canned(response_data),
    }
}

fn get_viewing_key(
    seed_phrase: Option<&str>,
    account_index: u32,
    network: crate::Network,
) -> Response {
    // GET_VK returns a big-endian u16 length followed by the UTF-8 UFVK.
    let value = derive_ufvk(seed_phrase, account_index, network);
    let mut payload = (value.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(value.as_bytes());
    canned(&response_data(&payload, 0x9000))
}
fn get_address(seed_phrase: Option<&str>, account_index: u32, network: crate::Network) -> Response {
    // Address responses are returned as a length-prefixed UTF-8 string by
    // the app.
    let value = derive_address(seed_phrase, account_index, network);
    let mut payload = (value.len() as u16).to_be_bytes().to_vec();
    payload.extend_from_slice(value.as_bytes());
    canned(&response_data(&payload, 0x9000))
}

pub(crate) fn seed(seed_phrase: Option<&str>) -> [u8; 64] {
    use bip39::Mnemonic;
    Mnemonic::parse(seed_phrase.unwrap_or("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
        .expect("seed phrase must be a valid BIP39 mnemonic")
        .to_seed("")
}

fn derive_ufvk(seed_phrase: Option<&str>, account_index: u32, network: crate::Network) -> String {
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_protocol::consensus::{MainNetwork, Parameters, TestNetwork};

    fn official_ufvk<P: Parameters>(uvk: UnifiedFullViewingKey, network: &P) -> String {
        use zcash_address::unified::{Encoding as _, Fvk, Ufvk};

        let value = Ufvk::try_from_items(vec![
            Fvk::P2pkh(
                uvk.transparent()
                    .expect("transparent key")
                    .serialize()
                    .try_into()
                    .expect("transparent key length"),
            ),
            Fvk::Orchard(uvk.orchard().expect("orchard key").to_bytes()),
        ])
        .expect("valid Official Ledger UFVK components");
        UnifiedFullViewingKey::parse(&value)
            .expect("valid Official Ledger UFVK")
            .encode(network)
    }

    let account = zip32::AccountId::try_from(account_index).expect("valid account index");
    let seed = seed(seed_phrase);
    match network {
        crate::Network::Mainnet => official_ufvk(
            UnifiedSpendingKey::from_seed(&MainNetwork, &seed, account)
                .unwrap()
                .to_unified_full_viewing_key(),
            &MainNetwork,
        ),
        crate::Network::Testnet => official_ufvk(
            UnifiedSpendingKey::from_seed(&TestNetwork, &seed, account)
                .unwrap()
                .to_unified_full_viewing_key(),
            &TestNetwork,
        ),
        crate::Network::Regtest => {
            let p = local_network();
            official_ufvk(
                UnifiedSpendingKey::from_seed(&p, &seed, account)
                    .unwrap()
                    .to_unified_full_viewing_key(),
                &p,
            )
        }
    }
}

fn derive_address(
    seed_phrase: Option<&str>,
    account_index: u32,
    network: crate::Network,
) -> String {
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
    use zcash_protocol::consensus::{MainNetwork, TestNetwork};
    let account = zip32::AccountId::try_from(account_index).expect("valid account index");
    let seed = seed(seed_phrase);
    match network {
        crate::Network::Mainnet => UnifiedSpendingKey::from_seed(&MainNetwork, &seed, account)
            .unwrap()
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .0
            .encode(&MainNetwork),
        crate::Network::Testnet => UnifiedSpendingKey::from_seed(&TestNetwork, &seed, account)
            .unwrap()
            .to_unified_full_viewing_key()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .unwrap()
            .0
            .encode(&TestNetwork),
        crate::Network::Regtest => {
            let p = local_network();
            UnifiedSpendingKey::from_seed(&p, &seed, account)
                .unwrap()
                .to_unified_full_viewing_key()
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .unwrap()
                .0
                .encode(&p)
        }
    }
}

fn local_network() -> zcash_protocol::local_consensus::LocalNetwork {
    use zcash_protocol::consensus::BlockHeight;
    let h = Some(BlockHeight::from_u32(1));
    zcash_protocol::local_consensus::LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        nu6_1: h,
        nu6_2: h,
        nu6_3: h,
        #[cfg(zcash_unstable = "nu7")]
        nu7: h,
    }
}
fn firmware_version() -> Response {
    // Ledger's firmware response is version bytes followed by SW_OK. Keep a
    // stable mock version so clients can exercise version parsing.
    canned(&response_data(b"80.0.0", 0x9000))
}
fn canned(response_data: &str) -> Response {
    Response {
        data: response_data.to_owned(),
        error: None,
    }
}

/// Encode an APDU payload followed by its two-byte status word.
pub(crate) fn response_data(payload: &[u8], status: u16) -> String {
    let mut response = payload.to_vec();
    response.extend_from_slice(&status.to_be_bytes());
    hex::encode(response)
}
