use std::time::{SystemTime, UNIX_EPOCH};

use crate::hotp::hotp_value;

type Bytes<'a> = &'a [u8];

const PERIOD: usize = 30; // in seconds

pub fn totp(key: Bytes) -> usize {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize;
    let counter = timestamp / PERIOD;
    hotp_value(key, counter)
}
