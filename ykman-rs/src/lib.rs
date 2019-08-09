use pyo3::prelude::pyfunction;
use pyo3::prelude::pymodule;
use pyo3::prelude::PyModule;
use pyo3::prelude::PyResult;
use pyo3::prelude::Python;
use pyo3::types::PyAny;
use pyo3::types::PyBytes;
use pyo3::types::PyString;
use pyo3::wrap_pyfunction;

use regex::bytes::Regex;

const PEM_IDENTIFIER: &str = &"-----BEGIN";

fn pem_regex() -> Regex {
    Regex::new(PEM_IDENTIFIER).expect("Failed to compile regex for PEM signature")
}

#[pyfunction]
fn is_pem(data: &PyAny) -> PyResult<bool> {
    if let Ok(data) = data.downcast_ref::<PyString>() {
        Ok(pem_regex().is_match(data.as_bytes()))
    } else if let Ok(data) = data.downcast_ref::<PyBytes>() {
        Ok(pem_regex().is_match(data.as_bytes()))
    } else {
        Ok(false)
    }
}

#[pymodule]
fn ykman_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(is_pem))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
