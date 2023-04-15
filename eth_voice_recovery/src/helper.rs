use crate::{
    DefaultVoiceRecoverCircuit, DefaultVoiceRecoverConfig, DefaultVoiceRecoverConfigParams,
    VOICE_RECOVER_CONFIG_ENV,
};
use clap::{Parser, Subcommand};
use halo2_base::halo2_proofs::circuit::Value;
use halo2_base::halo2_proofs::dev::MockProver;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::FieldExt;
use halo2_base::halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, VerifyingKey,
};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::halo2_proofs::poly::VerificationStrategy;
use halo2_base::halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWrite,
    TranscriptWriterBuffer,
};
use halo2_base::halo2_proofs::SerdeFormat;
use hex;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Pow;
use rand::rngs::OsRng;
use rand::thread_rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snark_verifier::loader::evm::EvmLoader;
use snark_verifier::pcs::kzg::{Gwc19, Kzg};
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use snark_verifier::verifier::{Plonk, PlonkVerifier};
use snark_verifier_sdk::evm::{encode_calldata, gen_evm_proof_gwc, gen_evm_verifier_gwc};
use snark_verifier_sdk::halo2::aggregation::PublicAggregationCircuit;
use snark_verifier_sdk::halo2::gen_snark_gwc;
use snark_verifier_sdk::{gen_pk, CircuitExt, LIMBS};
use std::env::set_var;
use std::fs::{self, File};
use std::io::BufRead;
use std::io::{BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

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
    commitment_hash: String,
    message: String,
    feature_hash: String,
    message_hash: String,
    // acc: String,
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
    params_dir: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    pk_dir: &str,
    vk_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    let app_params = {
        let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    // let agg_params = {
    //     let f = File::open(Path::new(params_dir).join("agg.bin")).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    // };
    let circuit = DefaultVoiceRecoverCircuit::default();
    let app_pk = gen_pk::<DefaultVoiceRecoverCircuit>(
        &app_params,
        &circuit,
        Some(&Path::new(pk_dir).join("app.pk")),
    );
    println!("app pk generated");
    // let snark = gen_snark_gwc(
    //     &app_params,
    //     &app_pk,
    //     circuit.clone(),
    //     &mut OsRng,
    //     None::<&str>,
    // );
    // println!("snark generated");
    // let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    // let agg_pk = gen_pk::<PublicAggregationCircuit>(
    //     &agg_params,
    //     &agg_circuit,
    //     Some(&Path::new(pk_dir).join("agg.pk")),
    // );
    // println!("agg pk generated");

    let vk = app_pk.get_vk();
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
    params_dir: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    pk_dir: &str,
    input_path: &str,
    proof_path: &str,
    public_input_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    let app_params = {
        let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    // let agg_params = {
    //     let f = File::open(Path::new(params_dir).join("agg.bin")).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    // };
    let app_pk = {
        let f = File::open(Path::new(pk_dir).join("app.pk")).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit>(
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
    let circuit = DefaultVoiceRecoverCircuit {
        features,
        errors,
        commitment,
        message,
    };
    let instances = circuit.instances();
    // let snark = gen_snark_gwc(&app_params, &app_pk, circuit, &mut OsRng, None::<&str>);
    // println!("app snark generated");
    // let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    // println!("agg_circuit created");
    // let prover = MockProver::run(agg_params.k(), &agg_circuit, agg_circuit.instances()).unwrap();
    // prover.assert_satisfied();
    // let agg_pk = {
    //     let f = File::open(Path::new(pk_dir).join("agg.pk")).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(
    //         &mut reader,
    //         SerdeFormat::RawBytesUnchecked,
    //     )
    //     .unwrap()
    // };
    // println!("agg_pk extracted");
    // let acc = agg_circuit.instances()[0][0..4 * LIMBS].to_vec();
    // let snark = gen_snark_gwc(&agg_params, &agg_pk, agg_circuit, &mut OsRng, None::<&str>);
    // println!("agg snark generated");

    let proof = {
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
            &app_params,
            &app_pk,
            &vec![circuit.clone()],
            &[&[instances[0].as_slice()]],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    {
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verifier_params = app_params.verifier_params();
        let strategy = SingleStrategy::new(&verifier_params);
        // let strategy = AccumulatorStrategy::new(verifier_params);
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            &app_params,
            &app_pk.get_vk(),
            strategy,
            &[&[instances[0].as_slice()]],
            &mut transcript,
        )
        .unwrap();
    };
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    let public_input = DefaultVoiceRecoverCircuitPublicInput {
        commitment_hash: format!("0x{}", hex::encode(instances[0][0].to_bytes()).as_str(),),
        feature_hash: format!("0x{}", hex::encode(instances[0][1].to_bytes()).as_str(),),
        message_hash: format!("0x{}", hex::encode(instances[0][2].to_bytes()).as_str()),
        message: input.message, // acc: format!(
                                //     "0x{}",
                                //     hex::encode(acc.iter().map(|v| v.get_lower_128() as u8).collect_vec(),).as_str()
                                // ),
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path)?;
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
    Ok(())
}

pub fn evm_prove(
    params_dir: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    pk_dir: &str,
    input_path: &str,
    proof_path: &str,
    public_input_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    // let params = {
    //     let f = File::open(params_path).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    // };
    let app_params = {
        let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    // let agg_params = {
    //     let f = File::open(Path::new(params_dir).join("agg.bin")).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    // };
    let app_pk = {
        let f = File::open(Path::new(pk_dir).join("app.pk")).unwrap();
        let mut reader = BufReader::new(f);
        ProvingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit>(
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
    let circuit = DefaultVoiceRecoverCircuit {
        features,
        errors,
        commitment,
        message,
    };
    let instances = circuit.instances();
    // let snark = gen_snark_gwc(&app_params, &app_pk, circuit, &mut OsRng, None::<&str>);
    // let agg_circuit = PublicAggregationCircuit::new(&agg_params, vec![snark], false, &mut OsRng);
    // let agg_instances = agg_circuit.instances();
    // let acc = agg_instances[0][0..4 * LIMBS].to_vec();
    // let agg_pk = {
    //     let f = File::open(Path::new(pk_dir).join("agg.pk")).unwrap();
    //     let mut reader = BufReader::new(f);
    //     ProvingKey::<G1Affine>::read::<_, PublicAggregationCircuit>(
    //         &mut reader,
    //         SerdeFormat::RawBytesUnchecked,
    //     )
    //     .unwrap()
    // };
    let proof = gen_evm_proof_gwc(&app_params, &app_pk, circuit, instances.clone(), &mut OsRng);

    // let proof = {
    //     let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
    //     create_proof::<KZGCommitmentScheme<_>, ProverGWC<_>, _, _, _, _>(
    //         &params,
    //         &pk,
    //         &vec![circuit.clone()],
    //         &[&instances
    //             .iter()
    //             .map(|instances| instances.as_slice())
    //             .collect_vec()],
    //         OsRng,
    //         &mut transcript,
    //     )
    //     .unwrap();
    //     transcript.finalize()
    // };
    {
        let f = File::create(proof_path).unwrap();
        let mut writer = BufWriter::new(f);
        writer.write_all(&proof).unwrap();
        writer.flush().unwrap();
    };
    // let acc_bytes = encode_calldata(&[acc], &[]);
    let public_input = DefaultVoiceRecoverCircuitPublicInput {
        commitment_hash: format!("0x{}", hex::encode(instances[0][0].to_bytes()).as_str(),),
        feature_hash: format!("0x{}", hex::encode(instances[0][1].to_bytes()).as_str(),),
        message_hash: format!("0x{}", hex::encode(instances[0][2].to_bytes()).as_str()),
        message: input.message, // acc: format!(
                                //     "0x{}",
                                //     hex::encode(acc.iter().map(|v| v.get_lower_128() as u8).collect_vec(),).as_str()
                                // ),
    };
    {
        let public_input_str = serde_json::to_string(&public_input).unwrap();
        let mut file = File::create(public_input_path)?;
        write!(file, "{}", public_input_str).unwrap();
        file.flush().unwrap();
    }
    Ok(())
}

pub fn verify(
    params_dir: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    vk_path: &str,
    public_input_path: &str,
    proof_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    let app_params = {
        let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit>(
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
    // let acc = hex::decode(&public_input.acc[2..]).unwrap();
    // let acc_public = acc.iter().map(|byte| Fr::from(*byte as u64)).collect_vec();
    let mut instances = vec![];
    let message = public_input.message.as_bytes().to_vec();
    let mut commitment_hash = [0; 32];
    commitment_hash.copy_from_slice(&hex::decode(&public_input.commitment_hash[2..]).unwrap());
    instances.push(Fr::from_bytes(&commitment_hash).unwrap());
    let mut feature_hash = [0; 32];
    feature_hash.copy_from_slice(&hex::decode(&public_input.feature_hash[2..]).unwrap());
    instances.push(Fr::from_bytes(&feature_hash).unwrap());
    let mut message_ext = message.to_vec();
    {
        let config_params = DefaultVoiceRecoverCircuit::read_config_params();
        message_ext.append(&mut vec![0; config_params.max_msg_size - message.len()]);
    }
    let mut packed_message = message_ext
        .chunks(16)
        .map(|bytes| Fr::from_u128(u128::from_le_bytes(bytes.try_into().unwrap())))
        .collect_vec();
    // let mut message_public = message
    //     .iter()
    //     .map(|byte| Fr::from(*byte as u64))
    //     .collect_vec();

    let mut message_hash = [0; 32];
    message_hash.copy_from_slice(&hex::decode(&public_input.message_hash[2..]).unwrap());
    instances.push(Fr::from_bytes(&message_hash).unwrap());
    instances.append(&mut packed_message);
    {
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let verifier_params = app_params.verifier_params();
        let strategy = SingleStrategy::new(&verifier_params);
        verify_proof::<_, VerifierGWC<_>, _, _, _>(
            &app_params,
            &vk,
            strategy,
            &[&[instances.as_slice()]],
            &mut transcript,
        )
        .unwrap();
    };
    Ok(())
}

pub fn gen_evm_verifier(
    params_dir: &str,
    app_circuit_config: &str,
    agg_circuit_config: &str,
    vk_path: &str,
    code_path: &str,
) -> Result<(), Error> {
    set_var(VOICE_RECOVER_CONFIG_ENV, app_circuit_config);
    set_var("VERIFY_CONFIG", agg_circuit_config);
    let app_params = {
        let f = File::open(Path::new(params_dir).join("app.bin")).unwrap();
        let mut reader = BufReader::new(f);
        ParamsKZG::<Bn256>::read(&mut reader).unwrap()
    };
    let vk = {
        let f = File::open(vk_path).unwrap();
        let mut reader = BufReader::new(f);
        VerifyingKey::<G1Affine>::read::<_, DefaultVoiceRecoverCircuit>(
            &mut reader,
            SerdeFormat::RawBytesUnchecked,
        )
        .unwrap()
    };
    let circuit_params = DefaultVoiceRecoverCircuit::read_config_params();
    let num_instances = vec![3 + circuit_params.max_msg_size / 16];
    let verifier_yul = {
        let svk = app_params.get_g()[0].into();
        let dk = (app_params.g2(), app_params.s_g2()).into();
        let protocol = compile(
            &app_params,
            &vk,
            Config::kzg()
                .with_num_instance(num_instances.clone())
                .with_accumulator_indices(DefaultVoiceRecoverCircuit::accumulator_indices()),
        );

        let loader = EvmLoader::new::<Fq, Fr>();
        let protocol = protocol.loaded(&loader);
        let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

        let instances = transcript.load_instances(num_instances);
        let proof =
            Plonk::<Kzg<Bn256, Gwc19>>::read_proof(&svk, &protocol, &instances, &mut transcript);
        Plonk::<Kzg<Bn256, Gwc19>>::verify(&svk, &dk, &protocol, &instances, &proof);
        loader.yul_code()
    };
    // let verifier = gen_evm_verifier_gwc::<DefaultVoiceRecoverCircuit>(
    //     &app_params,
    //     &vk,
    //     vec![num_instance],
    //     None,
    // );
    // let verifier_str = "0x".to_string() + &hex::encode(verifier);
    {
        let mut f = File::create(code_path).unwrap();
        let _ = f.write(verifier_yul.as_bytes());
        let output = fix_verifier_sol(Path::new(code_path).to_path_buf()).unwrap();

        let mut f = File::create(code_path)?;
        let _ = f.write(output.as_bytes());
        // write!(f, "{}", verifier_yul).unwrap();
        // let output = f.flush().unwrap();
    };
    Ok(())
}

pub fn fix_verifier_sol(input_file: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(input_file.clone())?;
    let reader = BufReader::new(file);

    let mut transcript_addrs: Vec<u32> = Vec::new();
    let mut modified_lines: Vec<String> = Vec::new();

    // convert calldataload 0x0 to 0x40 to read from pubInputs, and the rest
    // from proof
    let calldata_pattern = Regex::new(r"^.*(calldataload\((0x[a-f0-9]+)\)).*$")?;
    let mstore_pattern = Regex::new(r"^\s*(mstore\(0x([0-9a-fA-F]+)+),.+\)")?;
    let mstore8_pattern = Regex::new(r"^\s*(mstore8\((\d+)+),.+\)")?;
    let mstoren_pattern = Regex::new(r"^\s*(mstore\((\d+)+),.+\)")?;
    let mload_pattern = Regex::new(r"(mload\((0x[0-9a-fA-F]+))\)")?;
    let keccak_pattern = Regex::new(r"(keccak256\((0x[0-9a-fA-F]+))")?;
    let modexp_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start {
        end.unwrap() - s
    } else {
        0
    };

    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }

    let file = File::open(input_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line);
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line);
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;

            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(pubInputs, {}))", pub_addr),
                );
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(proof, {}))", proof_addr),
                );
            }
        }

        let m = mstore8_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore8(add(transcript, {})", transcript_addr),
            );
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 10)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = modexp_pattern.captures(&line);
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!(
                    "staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecmul_pattern.captures(&line);
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!(
                    "staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecadd_pattern.captures(&line);
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!(
                    "staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecpairing_pattern.captures(&line);
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!(
                    "staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = mstore_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = keccak_pattern.captures(&line);
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                keccak,
                &format!("keccak256(add(transcript, {})", transcript_addr),
            );
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line);
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mload,
                &format!("mload(add(transcript, {})", transcript_addr),
            );
        }

        modified_lines.push(line);
    }

    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;
    let mut contract = format!(
        "// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.17;
    
    contract Verifier {{
        function verify(
            uint256[] memory pubInputs,
            bytes memory proof
        ) public view returns (bool) {{
            bool success = true;
            bytes32[{}] memory transcript;
            assembly {{
        ",
        max_transcript_addr
    )
    .trim()
    .to_string();

    // using a boxed Write trait object here to show it works for any Struct impl'ing Write
    // you may also use a std::fs::File here
    let mut write: Box<&mut dyn std::fmt::Write> = Box::new(&mut contract);

    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        write!(write, "{}", line).unwrap();
    }
    writeln!(write, "}} return success; }} }}")?;
    Ok(contract)
}
