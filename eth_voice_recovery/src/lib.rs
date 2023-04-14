mod fuzzy;
use std::fs::File;
use std::marker::PhantomData;
mod helper;
use crate::fuzzy::*;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Cell, Region, SimpleFloorPlanner, Value};
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
use halo2_dynamic_sha256::{
    AssignedHashResult, Field, Sha256CompressionConfig, Sha256DynamicConfig,
};
pub use helper::*;
use itertools::Itertools;
use serde_json;
use snark_verifier_sdk::CircuitExt;

#[derive(Debug, Clone)]
pub struct VoiceRecoverResult<'a, F: Field> {
    pub assigned_commitment: Vec<AssignedValue<'a, F>>,
    pub assigned_feature_hash: Vec<AssignedValue<'a, F>>,
    pub assigned_message: Vec<AssignedValue<'a, F>>,
    pub assigned_message_hash: Vec<AssignedValue<'a, F>>,
    pub assigned_msg_len: AssignedValue<'a, F>,
}

#[derive(Debug, Clone)]
pub struct VoiceRecoverConfig<F: Field> {
    fuzzy_commitment: FuzzyCommitmentConfig<F>,
    msg_hash_sha256_config: Sha256DynamicConfig<F>,
    max_msg_size: usize,
}

impl<F: Field> VoiceRecoverConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        word_size: usize,
        max_msg_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        error_threshold: u64,
    ) -> Self {
        let fuzzy_commitment = FuzzyCommitmentConfig::<F>::configure(
            meta,
            num_sha2_compression_per_column,
            range_config.clone(),
            error_threshold,
            word_size,
        );
        let sha256_comp_configs = (0..num_sha2_compression_per_column)
            .map(|_| Sha256CompressionConfig::configure(meta))
            .collect();
        let max_size = word_size + max_msg_size;
        let max_size = max_size + (64 - (max_size % 64));
        let msg_hash_sha256_config =
            Sha256DynamicConfig::construct(sha256_comp_configs, max_size, range_config);
        Self {
            fuzzy_commitment,
            msg_hash_sha256_config,
            max_msg_size,
        }
    }

    pub fn auth_and_sign<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        features: &[u8],
        errors: &[u8],
        commitment: &[u8],
        message: &[u8],
    ) -> Result<VoiceRecoverResult<'a, F>, Error> {
        let fuzzy_result = self
            .fuzzy_commitment
            .recover_and_hash(ctx, features, errors, commitment)?;
        let mut message_ext = message.to_vec();
        message_ext.append(&mut vec![0; self.max_msg_size - message.len()]);
        let msg_hash_input_bytes = vec![fuzzy_result.word_value, message.to_vec()].concat();
        let msg_hash_result = self
            .msg_hash_sha256_config
            .digest(ctx, &msg_hash_input_bytes)?;
        let gate = self.gate();
        let assigned_message = message_ext
            .into_iter()
            .map(|val| gate.load_witness(ctx, Value::known(F::from(val as u64))))
            .collect_vec();
        for idx in 0..self.fuzzy_commitment.word_size {
            gate.assert_equal(
                ctx,
                QuantumCell::Existing(&msg_hash_result.input_bytes[idx]),
                QuantumCell::Existing(&fuzzy_result.assigned_word[idx]),
            );
        }
        let range = self.range();
        let msg_len = gate.sub(
            ctx,
            QuantumCell::Existing(&msg_hash_result.input_len),
            QuantumCell::Existing(&fuzzy_result.assigned_word_len),
        );
        for idx in 0..self.max_msg_size {
            let is_enable = range.is_less_than(
                ctx,
                QuantumCell::Constant(F::from(idx as u64)),
                QuantumCell::Existing(&msg_len),
                64,
            );
            let enabled_byte0 = gate.mul(
                ctx,
                QuantumCell::Existing(&is_enable),
                QuantumCell::Existing(
                    &msg_hash_result.input_bytes[self.fuzzy_commitment.word_size + idx],
                ),
            );
            let enabled_byte1 = gate.mul(
                ctx,
                QuantumCell::Existing(&is_enable),
                QuantumCell::Existing(&assigned_message[idx]),
            );
            gate.assert_equal(
                ctx,
                QuantumCell::Existing(&enabled_byte0),
                QuantumCell::Existing(&enabled_byte1),
            );
        }

        Ok(VoiceRecoverResult {
            assigned_commitment: fuzzy_result.assigned_commitment,
            assigned_feature_hash: fuzzy_result.assigned_feature_hash,
            assigned_message,
            assigned_message_hash: msg_hash_result.output_bytes,
            assigned_msg_len: msg_len,
        })
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.fuzzy_commitment.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.fuzzy_commitment.new_context(region)
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.fuzzy_commitment.finalize(ctx);
    }
}

pub const VOICE_RECOVER_CONFIG_ENV: &'static str = "EMAIL_VERIFY_CONFIG";
#[derive(serde::Serialize, serde::Deserialize)]
pub struct DefaultVoiceRecoverConfigParams {
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub num_sha2_compression_per_column: usize,
    pub error_threshold: u64,
    pub word_size: usize,
    pub max_msg_size: usize,
}

#[derive(Debug, Clone)]
pub struct DefaultVoiceRecoverConfig<F: Field> {
    inner: VoiceRecoverConfig<F>,
    commitment_public: Column<Instance>,
    feature_hash_public: Column<Instance>,
    message_public: Column<Instance>,
    message_hash_public: Column<Instance>,
}

#[derive(Debug, Clone)]
pub struct DefaultVoiceRecoverCircuit<F: Field> {
    pub features: Vec<u8>,
    pub errors: Vec<u8>,
    pub commitment: Vec<u8>,
    pub message: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: Field> Default for DefaultVoiceRecoverCircuit<F> {
    fn default() -> Self {
        let params = Self::read_config_params();
        let word_size = params.word_size;
        Self {
            features: vec![0; word_size],
            errors: vec![0; word_size],
            commitment: vec![0; word_size],
            message: vec![],
            _f: PhantomData,
        }
    }
}

impl<F: Field> Circuit<F> for DefaultVoiceRecoverCircuit<F> {
    type Config = DefaultVoiceRecoverConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let params = Self::read_config_params();
        let range_config = RangeConfig::configure(
            meta,
            Vertical,
            &[params.num_advice],
            &[params.num_lookup_advice],
            params.num_fixed,
            params.lookup_bits,
            0,
            params.degree as usize,
        );
        let inner = VoiceRecoverConfig::configure(
            meta,
            params.word_size,
            params.max_msg_size,
            params.num_sha2_compression_per_column,
            range_config,
            params.error_threshold,
        );
        let commitment_public = meta.instance_column();
        meta.enable_equality(commitment_public);
        let feature_hash_public = meta.instance_column();
        meta.enable_equality(feature_hash_public);
        let message_public = meta.instance_column();
        meta.enable_equality(message_public);
        let message_hash_public = meta.instance_column();
        meta.enable_equality(message_hash_public);
        Self::Config {
            inner,
            commitment_public,
            feature_hash_public,
            message_public,
            message_hash_public,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.inner.range().load_lookup_table(&mut layouter)?;
        let mut first_pass = SKIP_FIRST_PASS;
        let mut commitment_cell = vec![];
        let mut feature_hash_cell = vec![];
        let mut message_cell = vec![];
        let mut message_hash_cell = vec![];
        layouter.assign_region(
            || "voice recover",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = &mut config.inner.new_context(region);
                let result = config.inner.auth_and_sign(
                    ctx,
                    &self.features,
                    &self.errors,
                    &self.commitment,
                    &self.message,
                )?;
                config.inner.finalize(ctx);
                commitment_cell.append(
                    &mut result
                        .assigned_commitment
                        .into_iter()
                        .map(|v| v.cell())
                        .collect_vec(),
                );
                feature_hash_cell.append(
                    &mut result
                        .assigned_feature_hash
                        .into_iter()
                        .map(|v| v.cell())
                        .collect_vec(),
                );
                message_cell.append(
                    &mut result
                        .assigned_message
                        .into_iter()
                        .map(|v| v.cell())
                        .collect_vec(),
                );
                message_hash_cell.append(
                    &mut result
                        .assigned_message_hash
                        .into_iter()
                        .map(|v| v.cell())
                        .collect_vec(),
                );
                Ok(())
            },
        )?;
        for (idx, cell) in commitment_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.commitment_public, idx)?;
        }
        for (idx, cell) in feature_hash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.feature_hash_public, idx)?;
        }
        for (idx, cell) in message_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.message_public, idx)?;
        }
        for (idx, cell) in message_hash_cell.into_iter().enumerate() {
            layouter.constrain_instance(cell, config.message_hash_public, idx)?;
        }
        Ok(())
    }
}

impl<F: Field> DefaultVoiceRecoverCircuit<F> {
    pub fn read_config_params() -> DefaultVoiceRecoverConfigParams {
        let path = std::env::var(VOICE_RECOVER_CONFIG_ENV)
            .expect("You should set the configure file path to VOICE_RECOVER_CONFIG_ENV.");
        let params: DefaultVoiceRecoverConfigParams = serde_json::from_reader(
            File::open(path.as_str()).expect(&format!("{} does not exist.", path)),
        )
        .expect("File is found but invalid.");
        params
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_base::halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use rand::{seq::SliceRandom, thread_rng, Rng};
    use sha2::{Digest, Sha256};

    #[test]
    fn test_correct1() {
        temp_env::with_var(
            VOICE_RECOVER_CONFIG_ENV,
            Some("./configs/test1_circuit.config"),
            || {
                let vec_len = 256;
                let hamming_weight = 99;
                let features_bits = gen_random_vec_bits(vec_len);
                let word_bits = gen_random_vec_bits(vec_len);
                let error_bits = gen_error_term_bits(hamming_weight, vec_len);
                let commitment_bits = features_bits
                    .iter()
                    .zip(word_bits.iter())
                    .zip(error_bits.iter())
                    .map(|((f, w), e)| f ^ w ^ e)
                    .collect_vec();
                let features_bytes = bool_slice_to_le_bytes(&features_bits);
                println!("features_bytes {}", hex::encode(&features_bytes));
                let word_bytes = bool_slice_to_le_bytes(&word_bits);
                println!("word_bytes {}", hex::encode(&word_bytes));
                let error_bytes = bool_slice_to_le_bytes(&error_bits);
                println!("error_bytes {}", hex::encode(&error_bytes));
                let commitment_bytes = bool_slice_to_le_bytes(&commitment_bits);
                println!("commitment_bytes {}", hex::encode(&commitment_bytes));
                let message = b"test".to_vec();
                let commitment_public = commitment_bytes
                    .iter()
                    .map(|byte| Fr::from(*byte as u64))
                    .collect_vec();
                let feature_hash = Sha256::digest(&word_bytes).to_vec();
                println!("feature_hash {}", hex::encode(&feature_hash));
                let feature_hash_public = feature_hash
                    .into_iter()
                    .map(|byte| Fr::from(byte as u64))
                    .collect_vec();
                let message_public = message
                    .iter()
                    .map(|byte| Fr::from(*byte as u64))
                    .collect_vec();
                let message_hash =
                    Sha256::digest(&[word_bytes.to_vec(), message.to_vec()].concat()).to_vec();
                println!("message_hash {}", hex::encode(&message_hash));
                let message_hash_public = message_hash
                    .iter()
                    .map(|byte| Fr::from(*byte as u64))
                    .collect_vec();
                let circuit = DefaultVoiceRecoverCircuit::<Fr> {
                    features: features_bytes,
                    errors: error_bytes,
                    commitment: commitment_bytes,
                    message,
                    _f: PhantomData,
                };
                let prover = MockProver::run(
                    13,
                    &circuit,
                    vec![
                        commitment_public,
                        feature_hash_public,
                        message_public,
                        message_hash_public,
                    ],
                )
                .unwrap();
                assert_eq!(prover.verify(), Ok(()));
            },
        );
    }

    fn gen_random_vec_bits(vec_len: usize) -> Vec<bool> {
        let mut rng = rand::thread_rng();
        let mut result = vec![false; vec_len];
        for i in 0..vec_len {
            result[i] = rng.gen();
        }
        result
    }

    fn gen_error_term_bits(hamming_weight: usize, vec_len: usize) -> Vec<bool> {
        let mut rng = rand::thread_rng();
        let mut result = vec![false; vec_len];
        for i in 0..hamming_weight {
            result[i] = true;
        }
        result.shuffle(&mut rng);
        result
    }

    fn bool_slice_to_le_bytes(bool_slice: &[bool]) -> Vec<u8> {
        let mut result = vec![];
        for i in (0..bool_slice.len()).step_by(8) {
            let mut byte = 0u8;
            for j in 0..8 {
                if bool_slice[i + j] {
                    byte |= 1 << j;
                }
            }
            result.push(byte);
        }
        result
    }
}
