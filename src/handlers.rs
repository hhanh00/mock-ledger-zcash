#[allow(dead_code)]
#[derive(Debug)]
pub struct Apdu<'a> {
    cla: u8,
    ins: u8,
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

pub fn handle(apdu: &Apdu<'_>, response_data: &str) -> Response {
    const CLA_ZCASH: u8 = 0xE0;
    const INS_GET_VK: u8 = 0x50;
    const INS_GET_ADDRESS: u8 = 0x51;
    const INS_GET_FIRMWARE_VERSION: u8 = 0xC4;
    if apdu.cla != CLA_ZCASH {
        return canned(response_data);
    }
    match apdu.ins {
        INS_GET_VK => get_viewing_key(response_data),
        INS_GET_ADDRESS => get_address(response_data),
        0x52..=0x59 => pczt(response_data),
        INS_GET_FIRMWARE_VERSION => firmware_version(),
        _ => canned(response_data),
    }
}

fn get_viewing_key(response_data: &str) -> Response {
    canned(response_data)
}
fn get_address(response_data: &str) -> Response {
    canned(response_data)
}
fn pczt(response_data: &str) -> Response {
    canned(response_data)
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
fn response_data(payload: &[u8], status: u16) -> String {
    let mut response = payload.to_vec();
    response.extend_from_slice(&status.to_be_bytes());
    hex::encode(response)
}
