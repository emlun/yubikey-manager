use pyo3::prelude::Python;
use pyo3::types::PyString;
use pyo3::IntoPyObject;
use pyo3::PyObject;

pub struct Modhex {
    value: String,
}
impl Modhex {
    pub fn from_bytes(value: &[u8]) -> Modhex {
        Modhex {
            value: value.iter().map(byte_to_modhex_digits).fold(
                String::new(),
                |mut result, (msd, lsd)| {
                    result.push(msd);
                    result.push(lsd);
                    result
                },
            ),
        }
    }

    pub fn from_modhex(value: &str) -> Result<Modhex, ()> {
        if value.chars().all(|c| "cbdefghijklnrtuv".contains(c)) {
            Ok(Modhex {
                value: value.to_string(),
            })
        } else {
            Err(())
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let msds = self.value.chars().step_by(2);
        let lsds = self.value.chars().skip(1).step_by(2);
        msds.zip(lsds)
            .map(|(msd, lsd)| modhex_digit_to_byte(msd) * 16 + modhex_digit_to_byte(lsd))
            .collect()
    }

    fn as_string(&self) -> &String {
        &self.value
    }
}

impl IntoPyObject for Modhex {
    fn into_object(self, py: Python) -> PyObject {
        PyString::new(py, self.as_string()).into_object(py)
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

fn nibble_to_modhex_digit(n: u8) -> char {
    match n {
        0 => 'c',
        1 => 'b',
        2 => 'd',
        3 => 'e',
        4 => 'f',
        5 => 'g',
        6 => 'h',
        7 => 'i',
        8 => 'j',
        9 => 'k',
        10 => 'l',
        11 => 'n',
        12 => 'r',
        13 => 't',
        14 => 'u',
        15 => 'v',
        _ => panic!(format!("Out of modhex digit range: {}", n)),
    }
}

fn byte_to_modhex_digits(i: &u8) -> (char, char) {
    let msb = i / 16;
    let lsb = i % 16;
    (nibble_to_modhex_digit(msb), nibble_to_modhex_digit(lsb))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
