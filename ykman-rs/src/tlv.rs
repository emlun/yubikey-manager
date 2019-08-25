use std::convert::TryInto;

pub fn parse_tag(data: &[u8], offset: usize) -> (u16, u8) {
    let t: u16 = data[offset].into();

    if t & 0x1f != 0x1f {
        (t, 1)
    } else {
        let t = t << 8;
        let t2: u16 = data[offset + 1].into();
        (t | t2, 2)
    }
}

pub fn parse_length(data: &[u8], offset: usize) -> (u128, u8) {
    let ln: u8 = data[offset].into();
    let offset = offset + 1;

    if ln > 0x80 {
        let n_bytes: u8 = ln - 0x80;
        let mut be_bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for i in 0..n_bytes {
            let be_index: usize = (16 - n_bytes + i).try_into().unwrap();
            let i_usize: usize = i.try_into().unwrap();
            let data_index: usize = offset + i_usize;
            be_bytes[be_index] = data[data_index];
        }
        let ln: u128 = u128::from_be_bytes(be_bytes);
        (ln, n_bytes + 1)
    } else {
        (ln.into(), 1)
    }
}
