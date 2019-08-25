use pyo3::prelude::pymodule;
use pyo3::prelude::PyModule;
use pyo3::prelude::PyResult;
use pyo3::prelude::Python;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyString;

use regex::bytes::Regex;

const PEM_IDENTIFIER: &str = &"-----BEGIN";

fn pem_regex() -> Regex {
    Regex::new(PEM_IDENTIFIER).expect("Failed to compile regex for PEM signature")
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

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
