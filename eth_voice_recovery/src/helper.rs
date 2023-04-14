use crate::{
    DefaultVoiceRecoverCircuit, DefaultVoiceRecoverConfig, DefaultVoiceRecoverConfigParams,
    VOICE_RECOVER_CONFIG_ENV,
};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{keygen_pk, keygen_vk, Error, ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::Params;
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_base::halo2_proofs::SerdeFormat;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::evm::encode_calldata;
use snark_verifier_sdk::halo2::aggregation::AggregationCircuit;
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::env::set_var;
use std::fmt::format;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

pub fn gen_params(params_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

// pub fn gen_keys(params_path: &str, circuit_config: &str, pk: &str, vk: &str) -> Result<(), Error> {
//     set_var(VOICE_RECOVER_CONFIG_ENV, circuit_config);
//     let params = {
//         let f = File::open(params_path).unwrap();
//         let mut reader = BufReader::new(f);
//         ParamsKZG::<Bn256>::read(&mut reader).unwrap()
//     };
//     let pk = gen_pk(params, circuit, path)
// }
