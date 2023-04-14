use crate::{
    DefaultVoiceRecoverCircuit, DefaultVoiceRecoverConfig, DefaultVoiceRecoverConfigParams,
    VOICE_RECOVER_CONFIG_ENV,
};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, VerifyingKey,
};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::SerdeFormat;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::rngs::OsRng;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::env::set_var;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DefaultVoiceRecoverCircuitInput {
    features: String,
    errors: String,
    commitment: String,
    message: String,
    feature_hash: String,
    message_hash: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DefaultVoiceRecoverCircuitPublicInput {
    commitment: String,
    message: String,
    feature_hash: String,
    message_hash: String,
}

pub fn gen_params(params_path: &str, k: u32) -> Result<(), Error> {
    let rng = thread_rng();
    let params = ParamsKZG::<Bn256>::setup(k, rng);
    let f = File::create(params_path).unwrap();
    let mut writer = BufWriter::new(f);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();
    Ok(())
}

pub fn gen_keys(
    params_path: &str,
    circuit_config: &str,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, circuit_config);
    let params = {
        let f = File::open(params_path).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let circuit = DefaultVoiceRecoverCircuit::<Fr>::default();
    let pk = gen_pk::<DefaultVoiceRecoverCircuit<Fr>>(&params, &circuit, Some(&Path::new(pk_path)));
    let vk = pk.get_vk();
    {
        let f = File::create(vk_path).unwrap();
        let mut writer = BufWriter::new(f);
        vk.write(&mut writer, SerdeFormat::RawBytesUnchecked)
            .unwrap();
        writer.flush().unwrap();
    }
    Ok(())
}

pub fn prove(
    params_path: &str,
    circuit_config: &str,
    pk_path: &str,
    input_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, circuit_config);
    let params = {
        let f = File::open(params_path).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let pk = {
        let f = File::open(pk_path).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let input = serde_json::from_reader::<File, DefaultVoiceRecoverCircuitInput>(
        File::open(input_path).unwrap(),
    )
    .unwrap();
    let features = hex::decode(&input.features[2..]).unwrap();
    let errors = hex::decode(&input.errors[2..]).unwrap();
    let commitment = hex::decode(&input.commitment[2..]).unwrap();
    let message = input.message.as_bytes().to_vec();
    let commitment_public = commitment
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    let feature_hash = hex::decode(&input.feature_hash[2..]).unwrap();
    let feature_hash_public = feature_hash
        .into_iter()
        .map(|byte| Fr::from(byte as u64))
        .collect_vec();
    let message_public = message
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    let message_hash = hex::decode(&input.message_hash[2..]).unwrap();
    let message_hash_public = message_hash
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    let circuit = DefaultVoiceRecoverCircuit {
        features,
        errors,
        commitment,
        message,
        _f: PhantomData,
    };
    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &params,
            &pk,
            &vec![circuit.clone()],
            &[&[
                commitment_public.as_slice(),
                feature_hash_public.as_slice(),
                message_public.as_slice(),
                message_hash_public.as_slice(),
            ]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    Ok(())
}

pub fn verify(
    params_path: &str,
    circuit_config: &str,
    vk_path: &str,
    public_input_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, circuit_config);
    let params = {
        let f = File::open(params_path).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit<Fr>>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let public_input = serde_json::from_reader::<File, DefaultVoiceRecoverCircuitPublicInput>(
        File::open(public_input_path).unwrap(),
    )
    .unwrap();
    let proof = {
        let f = File::open(proof_path).unwrap();
        let mut reader = BufReader::new(f);
        let mut proof = vec![];
        reader.read_to_end(&mut proof).unwrap();
        proof
    };
    let commitment = hex::decode(&public_input.commitment[2..]).unwrap();
    let message = public_input.message.as_bytes().to_vec();
    let commitment_public = commitment
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    let feature_hash = hex::decode(&public_input.feature_hash[2..]).unwrap();
    let feature_hash_public = feature_hash
        .into_iter()
        .map(|byte| Fr::from(byte as u64))
        .collect_vec();
    let message_public = message
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    let message_hash = hex::decode(&public_input.message_hash[2..]).unwrap();
    let message_hash_public = message_hash
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect_vec();
    {
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&verifier_params);
        // let strategy = AccumulatorStrategy::new(verifier_params);
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            verifier_params,
            &vk,
            strategy,
            &[&[
                commitment_public.as_slice(),
                feature_hash_public.as_slice(),
                message_public.as_slice(),
                message_hash_public.as_slice(),
            ]],
            &mut transcript,
        )
        .unwrap();
    };
    Ok(())
}
