use pyo3::exceptions::TypeError;
use pyo3::exceptions::ValueError;
use pyo3::prelude::pymodule;
use pyo3::prelude::PyModule;
use pyo3::prelude::PyResult;
use pyo3::prelude::Python;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyString;
use pyo3::types::PyTuple;
use pyo3::IntoPyObject;
use pyo3::PyObject;

use regex::bytes::Regex;

const PEM_IDENTIFIER: &str = &"-----BEGIN";

struct Modhex(String);
impl Modhex {
    fn from_bytes(value: &[u8]) -> Modhex {
        Modhex(value.iter().map(byte_to_modhex_digits).fold(
            String::new(),
            |mut result, (msd, lsd)| {
                result.push(msd);
                result.push(lsd);
                result
            },
        ))
    }

    fn from_modhex(value: &str) -> Result<Modhex, ()> {
        for c in value.chars() {
            if "cbdefghijklnrtuv".contains(c) == false {
                return Err(());
            }
        }
        Ok(Modhex(value.to_string()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        let msds = self.0.chars().step_by(2);
        let lsds = self.0.chars().skip(1).step_by(2);
        msds.zip(lsds)
            .map(|(msd, lsd)| modhex_digit_to_byte(msd) * 16 + modhex_digit_to_byte(lsd))
            .collect()
    }
}

impl IntoPyObject for Modhex {
    fn into_object(self, py: Python) -> PyObject {
        PyString::new(py, &self.0).into_object(py)
    }
}

fn pem_regex() -> Regex {
    Regex::new(PEM_IDENTIFIER).expect("Failed to compile regex for PEM signature")
}

fn is_cve201715361_vulnerable_firmware_version(ver: (i64, i64, i64)) -> bool {
    (4, 2, 0) <= ver && ver < (4, 3, 5)
}

fn is_pem_bytes(data: &[u8]) -> bool {
    pem_regex().is_match(data)
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

#[pymodule]
fn ykman_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    #[pyfn(m, "is_pem")]
    fn py_is_pem(_py: Python, data: &PyAny) -> PyResult<bool> {
        if let Ok(data) = data.downcast_ref::<PyString>() {
            Ok(is_pem_bytes(data.as_bytes()))
        } else if let Ok(data) = data.downcast_ref::<PyBytes>() {
            Ok(is_pem_bytes(data.as_bytes()))
        } else {
            Ok(false)
        }
    }

    #[pyfn(m, "is_cve201715361_vulnerable_firmware_version")]
    fn py_is_cve201715361_vulnerable_firmware_version(
        py: Python,
        firmware_version: &PyTuple,
    ) -> PyResult<bool> {
        if let [maj, min, pat] = firmware_version.as_slice() {
            let ver: (i64, i64, i64) = (maj.extract(py)?, min.extract(py)?, pat.extract(py)?);
            Ok(is_cve201715361_vulnerable_firmware_version(ver))
        } else {
            Err(TypeError::py_err(format!(
                "Version must be (i64, i64, i64), was: {:?}",
                firmware_version
            )))
        }
    }

    #[pyfn(m, "modhex_encode")]
    fn py_modhex_encode(_py: Python, data: &PyBytes) -> Modhex {
        Modhex::from_bytes(data.as_bytes())
    }

    #[pyfn(m, "modhex_decode")]
    fn py_modhex_decode<'p>(py: Python<'p>, data: &PyString) -> PyResult<&'p PyBytes> {
        Modhex::from_modhex(data.to_string()?.as_ref())
            .map(|mh| PyBytes::new(py, mh.to_bytes().as_slice()))
            .or_else(|_| Err(ValueError::py_err(format!("Invalid modhex: {:?}", data))))
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
