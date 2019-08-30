mod modhex;
mod tlv;

use std::convert::TryFrom;
use std::convert::TryInto;

use regex::bytes::Regex;

use pyo3::exceptions::TypeError;
use pyo3::exceptions::ValueError;
use pyo3::prelude::pymodule;
use pyo3::prelude::PyModule;
use pyo3::prelude::PyResult;
use pyo3::prelude::Python;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyLong;
use pyo3::types::PyString;
use pyo3::types::PyTuple;
use pyo3::FromPyObject;
use pyo3::ToPyObject;

use modhex::Modhex;

const PEM_IDENTIFIER: &str = &"-----BEGIN";

fn pem_regex() -> Regex {
    Regex::new(PEM_IDENTIFIER).expect("Failed to compile regex for PEM signature")
}

fn is_cve201715361_vulnerable_firmware_version(ver: (i64, i64, i64)) -> bool {
    (4, 2, 0) <= ver && ver < (4, 3, 5)
}

fn is_pem_bytes(data: &[u8]) -> bool {
    pem_regex().is_match(data)
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
        Modhex::from(data.as_bytes())
    }

    #[pyfn(m, "modhex_decode")]
    fn py_modhex_decode<'p>(py: Python<'p>, data: &PyString) -> PyResult<&'p PyBytes> {
        Modhex::try_from(data.to_string()?.as_ref())
            .map(|mh| PyBytes::new(py, mh.as_bytes().as_slice()))
            .or_else(|_| Err(ValueError::py_err(format!("Invalid modhex: {:?}", data))))
    }

    #[pyfn(m, "tlv_parse_tag")]
    fn py_tlv_parse_tag(_py: Python, data: &PyBytes, offset: Option<usize>) -> (u16, usize) {
        tlv::parse_tag(data.as_bytes(), offset.unwrap_or(0))
    }

    #[pyfn(m, "tlv_parse_length")]
    fn py_tlv_parse_length(_py: Python, data: &PyBytes, offset: Option<usize>) -> (u128, usize) {
        tlv::parse_length(data.as_bytes(), offset.unwrap_or(0))
    }

    #[pyfn(m, "tlv_prepare_tlv_data")]
    fn py_tlv_prepare_tlv_data(
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
                    tag = u16::extract(data);
                    value = b"";
                } else if let Ok(data) = tag_or_data.downcast_ref::<PyBytes>() {
                    // Called with binary TLV data
                    let (_tag, tag_ln) = tlv::parse_tag(data.as_bytes(), 0);
                    tag = _tag;
                    let (ln, ln_ln) = tlv::parse_length(data.as_bytes(), tag_ln);
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

        return tlv::prepare_tlv_data_part2(tag, value)
            .map_err(|_| ValueError::py_err(format!("Unsupported tag value: {}", tag)));
    }

    Ok(())
}
