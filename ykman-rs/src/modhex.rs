use std::convert::TryFrom;

use pyo3::prelude::Python;
use pyo3::types::PyString;
use pyo3::IntoPyObject;
use pyo3::PyObject;

const MODHEX_DIGITS: &[u8] = b"cbdefghijklnrtuv";

pub struct Modhex {
    value: String,
}
impl Modhex {
    pub fn as_bytes(&self) -> Vec<u8> {
        let msds = self.value.chars().step_by(2);
        let lsds = self.value.chars().skip(1).step_by(2);
        msds.zip(lsds)
            .map(|(msd, lsd)| modhex_digit_to_byte(msd) * 16 + modhex_digit_to_byte(lsd))
            .collect()
    }

    fn as_str(&self) -> &str {
        &self.value
    }
}

impl From<&[u8]> for Modhex {
    fn from(value: &[u8]) -> Modhex {
        Modhex {
            value: value.iter().map(byte_to_modhex_digits).fold(
                String::new(),
                |mut result, (msd, lsd)| {
                    result.push(msd as char);
                    result.push(lsd as char);
                    result
                },
            ),
        }
    }
}

impl TryFrom<&str> for Modhex {
    type Error = ();

    fn try_from(value: &str) -> Result<Modhex, Self::Error> {
        if value.bytes().all(|c| MODHEX_DIGITS.contains(&c)) {
            Ok(Modhex {
                value: value.to_string(),
            })
        } else {
            Err(())
        }
    }
}

impl IntoPyObject for Modhex {
    fn into_object(self, py: Python) -> PyObject {
        PyString::new(py, self.as_str()).into_object(py)
    }
}

fn modhex_digit_to_byte(digit: char) -> u8 {
    match digit {
        'c' => 0,
        'b' => 1,
        'd' => 2,
        'e' => 3,
        'f' => 4,
        'g' => 5,
        'h' => 6,
        'i' => 7,
        'j' => 8,
        'k' => 9,
        'l' => 10,
        'n' => 11,
        'r' => 12,
        't' => 13,
        'u' => 14,
        'v' => 15,
        _ => panic!(format!("Invalid modhex digit: {}", digit)),
    }
}

fn nibble_to_modhex_digit(n: u8) -> u8 {
    MODHEX_DIGITS[n as usize]
}

fn byte_to_modhex_digits(i: &u8) -> (u8, u8) {
    let msb = i / 16;
    let lsb = i % 16;
    (nibble_to_modhex_digit(msb), nibble_to_modhex_digit(lsb))
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use quickcheck_macros::quickcheck;

    use super::Modhex;

    #[test]
    fn modhex_encode_is_correct() {
        assert_eq!("", Modhex::from(b"" as &[u8]).as_str());
        assert_eq!(
            "dteffuje",
            Modhex::from(b"\x2d\x34\x4e\x83" as &[u8]).as_str()
        );
        assert_eq!(
            "hknhfjbrjnlnldnhcujvddbikngjrtgh",
            Modhex::from(
                b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56" as &[u8]
            )
            .as_str()
        );
    }

    #[test]
    fn modhex_decode_is_correct() -> Result<(), ()> {
        assert_eq!(b"", &Modhex::try_from("")?.as_bytes().as_slice());
        assert_eq!(
            b"\x2d\x34\x4e\x83",
            Modhex::try_from("dteffuje")?.as_bytes().as_slice()
        );
        assert_eq!(
            b"\x69\xb6\x48\x1c\x8b\xab\xa2\xb6\x0e\x8f\x22\x17\x9b\x58\xcd\x56",
            Modhex::try_from("hknhfjbrjnlnldnhcujvddbikngjrtgh")?
                .as_bytes()
                .as_slice()
        );
        Ok(())
    }

    #[quickcheck]
    fn encode_then_decode_is_identity(data: Vec<u8>) -> bool {
        data == Modhex::from(data.as_slice()).as_bytes()
    }

    #[quickcheck]
    fn modhex_length_is_twice_byte_length(data: Vec<u8>) -> bool {
        2 * data.len() == Modhex::from(data.as_slice()).as_str().len()
    }
}
