use sha_256::Sha256;

fn u8a_to_hex(u8a: &[u8]) -> String {
    let mut hex = String::new();
    for byte in u8a {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

fn main() {
    let mut sha256: Sha256 = Sha256::new();
    // Message can be [u8] or Vec<u8>
    let message: String = "hello".to_string();
    println!("Message: {}", message);
    let message_bytes: &[u8] = message.as_bytes();
    let hash: [u8; 32] = sha256.digest(message_bytes);
    // convert the hash to a hex string
    let hash_hex = u8a_to_hex(&hash);
    println!("Hash: {}", hash_hex);
}
