use bytes::BytesMut;

pub(crate) fn add_bytes(bytes: &mut BytesMut, other: i8) {
    let mut to_add = other as i16;
    for byte in bytes.iter_mut().rev() {
        to_add += *byte as i16;
        *byte = to_add as u8;
        to_add >>= 8;
        if to_add == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_bytes_simple() {
        let mut bytes1 = BytesMut::from(&[1, 2, 3, 4][..]);
        add_bytes(&mut bytes1, 5);
        assert_eq!(bytes1, &[1, 2, 3, 9][..]);
    }

    #[test]
    fn test_add_bytes_overflow() {
        let mut bytes1 = BytesMut::from(&[1, 2, 3, 253][..]);
        add_bytes(&mut bytes1, 5);
        assert_eq!(bytes1, &[1, 2, 4, 2][..]);
    }

    #[test]
    fn test_add_bytes_underflow() {
        let mut bytes1 = BytesMut::from(&[1, 2, 3, 4][..]);
        add_bytes(&mut bytes1, -5);
        assert_eq!(bytes1, &[1, 2, 2, 255][..]);
    }
}
