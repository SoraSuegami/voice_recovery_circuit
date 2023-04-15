use eth_voice_recovery;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Cell, Region, SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{
    gates::{range::RangeStrategy::Vertical, RangeInstructions},
    ContextParams, SKIP_FIRST_PASS,
};
use halo2_base::{AssignedValue, QuantumCell};
use hex;
use pyo3::exceptions::{PyIOError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use snark_verifier_sdk::evm::encode_calldata;

#[pyfunction]
pub fn poseidon_hash(input_hex: String) -> PyResult<String> {
    let input = hex::decode(&input_hex[2..]).expect("invalid hex input");
    let out_fr = eth_voice_recovery::poseidon_circuit::poseidon_hash(&input);
    let out_hex = format!(
        "0x{}",
        hex::encode(encode_calldata(&[vec![out_fr]], &[])).as_str(),
    );
    Ok(out_hex)
}

#[pyfunction]
pub fn evm_prove(
    params_dir: String,
    app_circuit_config: String,
    agg_circuit_config: String,
    pk_dir: String,
    input_path: String,
    proof_path: String,
    public_input_path: String,
) -> PyResult<()> {
    eth_voice_recovery::helper::evm_prove(
        &params_dir,
        &app_circuit_config,
        &agg_circuit_config,
        &pk_dir,
        &input_path,
        &proof_path,
        &public_input_path,
    )
    .unwrap();
    Ok(())
}

#[pymodule]
fn voice_recovery_python(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    pyo3_log::init();
    m.add_function(wrap_pyfunction!(poseidon_hash, m)?)?;
    m.add_function(wrap_pyfunction!(evm_prove, m)?)?;
    Ok(())
}
