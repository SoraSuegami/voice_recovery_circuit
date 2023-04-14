mod fuzzy;
use std::fs::File;
use std::marker::PhantomData;

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
use halo2_dynamic_sha256::Field;
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
}

impl<F: Field> VoiceRecoverConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_byte_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        error_threshold: u64,
    ) -> Self {
        let fuzzy_commitment = FuzzyCommitmentConfig::<F>::configure(
            meta,
            max_byte_size,
            num_sha2_compression_per_column,
            range_config,
            error_threshold,
        );
        Self { fuzzy_commitment }
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
        let msg_hash_input_bytes = vec![fuzzy_result.word_value, message.to_vec()].concat();
        let msg_hash_result = self
            .fuzzy_commitment
            .sha256_config
            .digest(ctx, &msg_hash_input_bytes)?;
        let gate = self.gate();
        let assigned_message = message
            .into_iter()
            .map(|val| gate.load_witness(ctx, Value::known(F::from(*val as u64))))
            .collect_vec();
        let assigned_msg_hash_input =
            vec![fuzzy_result.assigned_word, assigned_message.clone()].concat();
        for (byte0, byte1) in msg_hash_result
            .input_bytes
            .iter()
            .zip(assigned_msg_hash_input.iter())
        {
            gate.assert_equal(
                ctx,
                QuantumCell::Existing(&byte0),
                QuantumCell::Existing(&byte1),
            );
        }
        let msg_len = gate.sub(
            ctx,
            QuantumCell::Existing(&msg_hash_result.input_len),
            QuantumCell::Existing(&fuzzy_result.assigned_word_len),
        );
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
    pub msg_max_byte_size: usize,
    pub error_threshold: u64,
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

impl<F: Field> Circuit<F> for DefaultVoiceRecoverCircuit<F> {
    type Config = DefaultVoiceRecoverConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            features: vec![],
            errors: vec![],
            commitment: vec![],
            message: vec![],
            _f: PhantomData,
        }
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
            params.msg_max_byte_size,
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
                let ctx = &mut Context::new(
                    region,
                    ContextParams {
                        max_rows: config.inner.gate().max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.inner.gate().constants.clone(),
                    },
                );
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
