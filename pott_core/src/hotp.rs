use crate::hmac::hmac;

type Bytes<'a> = &'a [u8];

const D: u32 = 6;

type MAC = [u8; 20];

fn to_binary(n: u8) -> [u8; 8] {
    let mut out_binary = [0; 8];
    for (i, b) in format!("{:08b}", n).chars().enumerate() {
        out_binary[i] = if b == '0' { 0 } else { 1 };
    }
    out_binary
}

fn bytes_to_binary(arr: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    for n in arr {
        out.append(&mut to_binary(*n).to_vec());
    }
    out
}

fn to_base10(binary: &[u8]) -> usize {
    let mut n = 0;
    for (power, b) in binary.iter().rev().enumerate() {
        n += *b as usize * 2_usize.pow(power as u32);
    }
    n
}

fn extract31(mac: MAC, i: usize) -> Vec<u8> {
    let mac_bin = bytes_to_binary(&mac);
    mac_bin[(i * 8 + 1)..=(i * 8 + 4 * 8 - 1)].to_vec()
}

fn truncate(mac: MAC) -> Vec<u8> {
    let offset = to_base10(&to_binary(mac[19])[4..8]);
    extract31(mac, offset)
}

fn hotp(key: Bytes, counter: usize) -> usize {
    let naked_mac = hmac(key, &counter.to_be_bytes()); // big endian neccessary here
    to_base10(&truncate(naked_mac))
}

pub fn hotp_value(key: Bytes, counter: usize) -> usize {
    hotp(key, counter) % 10_usize.pow(D)
}
