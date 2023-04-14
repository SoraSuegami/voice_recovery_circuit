use halo2_base::halo2_proofs::circuit::{Region, Value};
use halo2_base::halo2_proofs::plonk::ConstraintSystem;
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::QuantumCell;
use halo2_base::{
    gates::{flex_gate::FlexGateConfig, range::RangeConfig, GateInstructions, RangeInstructions},
    AssignedValue, Context,
};
use halo2_dynamic_sha256::{
    Field, Sha256AssignedRows, Sha256CompressionConfig, Sha256DynamicConfig,
};
use itertools::Itertools;

#[derive(Debug, Clone)]
pub struct FuzzyCommitmentResult<'a, F: Field> {
    pub(crate) assigned_commitment: Vec<AssignedValue<'a, F>>,
    pub(crate) assigned_feature_hash: Vec<AssignedValue<'a, F>>,
    pub(crate) assigned_word: Vec<AssignedValue<'a, F>>,
    pub(crate) assigned_word_len: AssignedValue<'a, F>,
    pub(crate) word_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct FuzzyCommitmentConfig<F: Field> {
    pub(crate) sha256_config: Sha256DynamicConfig<F>,
    error_threshold: u64,
}

impl<F: Field> FuzzyCommitmentConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        max_byte_size: usize,
        num_sha2_compression_per_column: usize,
        range_config: RangeConfig<F>,
        error_threshold: u64,
    ) -> Self {
        let sha256_comp_configs = (0..num_sha2_compression_per_column)
            .map(|_| Sha256CompressionConfig::configure(meta))
            .collect();
        let sha256_config =
            Sha256DynamicConfig::construct(sha256_comp_configs, max_byte_size, range_config);
        Self {
            sha256_config,
            error_threshold,
        }
    }

    pub fn recover_and_hash<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        features: &[u8],
        errors: &[u8],
        commitment: &[u8],
    ) -> Result<FuzzyCommitmentResult<'a, F>, Error> {
        assert_eq!(features.len(), errors.len());
        assert_eq!(errors.len(), commitment.len());
        let range = self.range();
        let gate = self.gate();
        let assigned_features = features
            .into_iter()
            .map(|val| gate.load_witness(ctx, Value::known(F::from(*val as u64))))
            .collect_vec();
        let assigned_errors = errors
            .into_iter()
            .map(|val| gate.load_witness(ctx, Value::known(F::from(*val as u64))))
            .collect_vec();
        let assigned_commitment = commitment
            .into_iter()
            .map(|val| gate.load_witness(ctx, Value::known(F::from(*val as u64))))
            .collect_vec();
        let features_bits = self.bytes2bits(ctx, &assigned_features);
        let errors_bits = self.bytes2bits(ctx, &assigned_errors);
        let commitment_bits = self.bytes2bits(ctx, &assigned_commitment);

        // 1. word errored = features XOR commitment
        let w_e = features_bits
            .iter()
            .zip(commitment_bits.iter())
            .map(|(f, c)| self.xor(ctx, &f, &c))
            .collect_vec();
        // 2. word = word errored XOR error
        let word_bits = w_e
            .iter()
            .zip(errors_bits.iter())
            .map(|(y, e)| self.xor(ctx, &y, &e))
            .collect_vec();
        let word_bytes = word_bits
            .chunks(8)
            .map(|bits| {
                let mut byte = gate.load_zero(ctx);
                for (idx, bit) in bits.into_iter().enumerate() {
                    byte = gate.mul_add(
                        ctx,
                        QuantumCell::Existing(&bit),
                        QuantumCell::Constant(F::from(1u64 << idx)),
                        QuantumCell::Existing(&byte),
                    );
                }
                byte
            })
            .collect_vec();
        // 3. |e| < t
        let mut e_weight = gate.load_zero(ctx);
        for (idx, bit) in errors_bits.iter().enumerate() {
            e_weight = gate.add(
                ctx,
                QuantumCell::Existing(&e_weight),
                QuantumCell::Existing(&bit),
            );
        }
        range.check_less_than_safe(ctx, &e_weight, self.error_threshold);
        let word_values = features
            .iter()
            .zip(errors.iter())
            .zip(commitment.iter())
            .map(|((f, e), c)| f ^ e ^ c)
            .collect_vec();
        let assigned_hash_result = self.sha256_config.digest(ctx, &word_values)?;
        for (w, h) in word_bytes
            .iter()
            .zip(assigned_hash_result.input_bytes.iter())
        {
            gate.assert_equal(ctx, QuantumCell::Existing(w), QuantumCell::Existing(h));
        }
        Ok(FuzzyCommitmentResult {
            assigned_commitment,
            assigned_feature_hash: assigned_hash_result.output_bytes,
            assigned_word: word_bytes,
            assigned_word_len: assigned_hash_result.input_len,
            word_value: word_values,
        })
    }

    pub fn range(&self) -> &RangeConfig<F> {
        self.sha256_config.range()
    }

    pub fn gate(&self) -> &FlexGateConfig<F> {
        self.range().gate()
    }

    pub fn new_context<'a, 'b>(&'b self, region: Region<'a, F>) -> Context<'a, F> {
        self.sha256_config.new_context(region)
    }

    pub fn finalize(&self, ctx: &mut Context<F>) {
        self.range().finalize(ctx);
    }

    fn bytes2bits<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        assigned_bytes: &[AssignedValue<'a, F>],
    ) -> Vec<AssignedValue<'a, F>> {
        let gate = self.gate();
        let bits = assigned_bytes
            .into_iter()
            .flat_map(|byte| gate.num_to_bits(ctx, byte, 8))
            .collect_vec();
        assert_eq!(assigned_bytes.len() * 8, bits.len());
        bits
    }

    fn xor<'v: 'a, 'a>(
        &self,
        ctx: &mut Context<'v, F>,
        a: &AssignedValue<'a, F>,
        b: &AssignedValue<'a, F>,
    ) -> AssignedValue<'a, F> {
        let gate = self.gate();
        let a_not = gate.not(ctx, QuantumCell::Existing(&a));
        let b_not = gate.not(ctx, QuantumCell::Existing(&b));
        let ab_not = gate.and(
            ctx,
            QuantumCell::Existing(&a),
            QuantumCell::Existing(&b_not),
        );
        let ba_not = gate.and(
            ctx,
            QuantumCell::Existing(&b),
            QuantumCell::Existing(&a_not),
        );
        gate.or(
            ctx,
            QuantumCell::Existing(&ab_not),
            QuantumCell::Existing(&ba_not),
        )
    }
}
