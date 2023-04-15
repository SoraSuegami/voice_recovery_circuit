Follow this document to call rust from python
https://pyo3.rs/v0.18.3/getting_started

How to rebuild
```
poetry install
poetry shell
cd voice_recovery_python
maturin develop
```

Setup

GenParams -> GenKeys -> GenEvmVerifier

見るべきファイルはこちらを参考に

```
EvmProve {
        /// setup parameter file
        #[arg(short, long, default_value = "./build/params")]
        params_dir: String,
        /// circuit configure file
        #[arg(
            short,
            long,
            default_value = "./eth_voice_recovery/configs/test1_circuit.config"
        )]
        app_circuit_config: String,
        #[arg(
            short,
            long,
            default_value = "./eth_voice_recovery/configs/agg_circuit.config"
        )]
        agg_circuit_config: String,
        /// proving key file path
        #[arg(long, default_value = "./build/pks")]
        pk_dir: String,
        /// input file path
        #[arg(long, default_value = "./build/input.json")]
        input_path: String,
        /// proof file path
        #[arg(long, default_value = "./build/evm_proof.hex")]
        proof_path: String,
        /// public input file path
        #[arg(long, default_value = "./build/evm_public_input.json")]
        public_input_path: String,
    },
```