use sha1::{Digest, Sha1};

const BLOCK_SIZE: usize = 64;

type Bytes<'a> = &'a [u8];

fn hash(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn pad_zeroes<const B: usize>(arr: &[u8]) -> [u8; B] {
    // assert!(B >= arr.len());
    let mut b = [0; B];
    b[..arr.len()].copy_from_slice(arr);
    b
}

fn xor_array<const A: usize>(a: &[u8; A], b: &[u8; A]) -> [u8; A] {
    let mut c = [0; A];
    for i in 0..A {
        c[i] = a[i] ^ b[i]
    }
    c
}

fn concat<const A: usize, const B: usize, const C: usize>(a: &[u8; A], b: &[u8; B]) -> [u8; C] {
    let mut whole: [u8; C] = [0; C];
    let (one, two) = whole.split_at_mut(A);
    one.copy_from_slice(a);
    two.copy_from_slice(b);
    whole
}

pub fn hmac(key: Bytes, message: Bytes) -> [u8; 20] {
    let block_sized_key = if key.len() > BLOCK_SIZE {
        pad_zeroes::<BLOCK_SIZE>(&hash(key))
    } else {
        pad_zeroes::<BLOCK_SIZE>(key)
    };

    let o_key_pad = xor_array::<BLOCK_SIZE>(&block_sized_key, &[0x5c; BLOCK_SIZE]);
    let i_key_pad = xor_array::<BLOCK_SIZE>(&block_sized_key, &[0x36; BLOCK_SIZE]);

    let mconcatikp = [i_key_pad.to_vec(), message.to_vec()].concat();
    hash(&concat::<BLOCK_SIZE, 20, { BLOCK_SIZE + 20 }>(
        &o_key_pad,
        &hash(&mconcatikp),
    ))
}
