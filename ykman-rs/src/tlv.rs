use std::convert::TryInto;

use pyo3::exceptions::ValueError;
use pyo3::prelude::PyResult;
use pyo3::prelude::Python;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyLong;
use pyo3::ToPyObject;

fn add_u128_leading_zeroes(bytes: &[u8], len: usize) -> [u8; 16] {
    let mut padded: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for i in 0..len {
        let result_index: usize = (16 - len + i).try_into().unwrap();
        let input_index: usize = i.try_into().unwrap();
        padded[result_index] = bytes[input_index];
    }
    padded
}

pub fn parse_tag(data: &[u8], offset: usize) -> (u16, usize) {
    let t: u16 = data[offset].into();

    if t & 0x1f != 0x1f {
        (t, 1)
    } else {
        let t = t << 8;
        let t2: u16 = data[offset + 1].into();
        (t | t2, 2)
    }
}

pub fn parse_length(data: &[u8], offset: usize) -> (u128, usize) {
    let ln: u8 = data[offset].into();
    let offset = offset + 1;

    if ln > 0x80 {
        let n_bytes: u8 = ln - 0x80;
        let be_bytes: [u8; 16] =
            add_u128_leading_zeroes(&data[offset..], n_bytes.try_into().unwrap());
        let ln: u128 = u128::from_be_bytes(be_bytes);
        (ln, (n_bytes + 1).try_into().unwrap())
    } else {
        (ln.into(), 1)
    }
}

pub fn prepare_tlv_data(
    py: Python,
    tag_or_data: &PyAny,
    data: Option<&PyBytes>,
) -> PyResult<Vec<u8>> {
    let tag: u16;
    let value: &[u8];

    match data {
        None => {
            if let Ok(data) = tag_or_data.downcast_ref::<PyLong>() {
                // Called with tag only, blank value
                tag = data.to_object(py).extract(py)?;
                value = b"";
            } else if let Ok(data) = tag_or_data.downcast_ref::<PyBytes>() {
                // Called with binary TLV data
                let (_tag, tag_ln) = parse_tag(data.as_bytes(), 0);
                tag = _tag;
                let (ln, ln_ln) = parse_length(data.as_bytes(), tag_ln);
                let offs = tag_ln + ln_ln;
                let end: usize = (ln + (offs as u128)).try_into().unwrap();
                value = &data.as_bytes()[offs..end];
            } else {
                panic!()
            }
        }
        Some(val) => {
            // Called with tag and value.
            tag = tag_or_data
                .downcast_ref::<PyLong>()?
                .to_object(py)
                .extract(py)?;
            value = val.as_bytes();
        }
    }

    return prepare_tlv_data_part2(tag, value)
        .map_err(|_| ValueError::py_err(format!("Unsupported tag value: {}", tag)));
}

pub fn prepare_tlv_data_part2(tag: u16, value: &[u8]) -> Result<Vec<u8>, ()> {
    let mut data: Vec<u8> = vec![];

    if tag <= 0xff {
        data.push(tag.try_into().unwrap());
    } else {
        let tag_1: u8 = (tag >> 8).try_into().unwrap();

        if tag_1 & 0x1f != 0x1f {
            return Err(());
        }

        let tag_2: u8 = (tag & 0xff).try_into().unwrap();
        data.push(tag_1);
        data.push(tag_2);
    }

    let length: usize = value.len();

    if length < 0x80 {
        data.push(length.try_into().unwrap());
    } else if length < 0xff {
        data.push(0x81);
        data.push(length.try_into().unwrap());
    } else {
        data.push(0x82);
        let msb: u8 = (length >> 8).try_into().unwrap();
        let lsb: u8 = (length & 0xff).try_into().unwrap();
        data.push(msb);
        data.push(lsb);
    }
    for b in value {
        data.push(*b);
    }
    Ok(data)
}
