use pyo3::prelude::*;

#[pymodule]
fn _sondare(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    Ok(())
}
