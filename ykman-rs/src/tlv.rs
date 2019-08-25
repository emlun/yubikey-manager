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
