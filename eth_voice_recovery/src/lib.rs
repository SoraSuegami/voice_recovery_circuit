mod fuzzy;
use std::marker::PhantomData;

use crate::fuzzy::*;
use halo2_base::halo2_proofs::circuit::{AssignedCell, Cell, Region, SimpleFloorPlanner, Value};
use halo2_base::halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Instance};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions},
    utils::PrimeField,
    Context,
};
use halo2_base::{AssignedValue, QuantumCell};
use halo2_dynamic_sha256::Field;
use itertools::Itertools;

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
        &'v self,
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
        let gate = self.fuzzy_commitment.gate();
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
}
