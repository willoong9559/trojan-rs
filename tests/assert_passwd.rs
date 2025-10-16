use trojan_rs::utils;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_hex() {
        let password = "2bd334f9-fbc9-74ea-8ecb-bbb56771999d";
        let expected: [u8; 56] = [
            51, 55, 102, 100, 97, 48, 101, 98, 52, 52, 100, 50, 100, 55, 54, 100, 53, 53, 56, 100,
            101, 52, 53, 97, 55, 49, 56, 99, 53, 98, 54, 52, 98, 53, 48, 97, 102, 50, 50, 101, 53,
            57, 48, 57, 53, 100, 56, 52, 57, 54, 54, 99, 97, 50, 53, 100,
        ];

        let hex_bytes = utils::password_to_hex(password);
        assert_eq!(hex_bytes, expected);
    }
}
