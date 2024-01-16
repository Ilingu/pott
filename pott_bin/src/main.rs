use pott_core::totp::totp;

fn main() {
    let current_totp = totp("54L4FGWCU6ZKO7OU".as_bytes());
    println!("{current_totp}")
}
