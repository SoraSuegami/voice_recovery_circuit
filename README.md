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

Public Inputの中身
```
pub struct DefaultVoiceRecoverCircuitPublicInput {
    commitment: String,
    commitment_hash: String,
    message: String,
    feature_hash: String,
    message_hash: String,
    // acc: String,
}
```

Secret Inputの中身
```
{
    "features": "0x52ad6993e8ed48b87023fa32cb416c49b4e0b87c2c63a8ea8e68818c776d9e7f8efc64a1f3b96e806ec2bc9fb4301ce7c9b47ac29ca143d25ca3b082b8f76c207dcaa671ca4df240d277ffde7d4d37887266e923cc51910039f485823dba94dc02da01bca68bbb7b79695b693341eca4bbd955714e6155d2eb641762a307c2c7e0c021fabb817da4f720f9f9",
    "errors": "0x02000401080080007000040030000110000000000090090010024000000c08008000000000040000000080002000000001c044001800000000080100440100000a00000000004000000000001298a400000049800004900080400000000000000031080110004800200801608410040020000000801000018212000022100000002401160380200080010000",
    "commitment": "0xb577b007bd3c08abfb74aa19c01395a00788c7862913953def64406050c7322ab5a393558c081b143a325c1de06856846f80704900df75be381216f53d7f6651d2557dae5c029b3cc0fbb671f53e11a1745466b4b1d4f39cf52c9e389bfe58796013ee4031816e839041cde2dc8d212ddf488834de1de7164e7f87b0e5ac1af210374da374ca572751247a8a",
    "message": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb9226670997970c51812dc3a010c7d01b50e0d17dc79c8"
}
```