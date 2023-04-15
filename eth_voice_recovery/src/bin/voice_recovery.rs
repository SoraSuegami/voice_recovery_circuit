use clap::{Parser, Subcommand};
use eth_voice_recovery::*;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    /// Generate a setup parameter (not for production).
    GenParams {
        /// k parameter
        #[arg(long)]
        k: u32,
        /// setup parameter path
        #[arg(short, long)]
        params_path: String,
    },
    /// Generate a proving key and a verifying key.
    GenKeys {
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
        /// verifying key file path
        #[arg(long, default_value = "./build/agg.vk")]
        vk_path: String,
    },
    Prove {
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
        #[arg(long, default_value = "./build/proof.bin")]
        proof_path: String,
        /// public input file path
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
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
        #[arg(long, default_value = "./build/proof.bin")]
        proof_path: String,
        /// public input file path
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
    },
    Verify {
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
        /// verifying key file path
        #[arg(long, default_value = "./build/agg.vk")]
        vk_path: String,
        /// public input file path
        #[arg(long, default_value = "./build/public_input.json")]
        public_input_path: String,
        /// proof file path
        #[arg(long, default_value = "./build/proof.bin")]
        proof_path: String,
    },
    GenEvmVerifier {
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
        /// verifying key file path
        #[arg(long, default_value = "./build/agg.vk")]
        vk_path: String,
        /// verifier code path
        #[arg(long, default_value = "./build/verifier_code.txt")]
        code_path: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(&params_path, k).unwrap(),
        Commands::GenKeys {
            params_dir,
            app_circuit_config,
            agg_circuit_config,
            pk_dir,
            vk_path,
        } => gen_keys(
            &params_dir,
            &app_circuit_config,
            &agg_circuit_config,
            &pk_dir,
            &vk_path,
        )
        .unwrap(),
        Commands::Prove {
            params_dir,
            app_circuit_config,
            agg_circuit_config,
            pk_dir,
            input_path,
            proof_path,
            public_input_path,
        } => prove(
            &params_dir,
            &app_circuit_config,
            &agg_circuit_config,
            &pk_dir,
            &input_path,
            &proof_path,
            &public_input_path,
        )
        .unwrap(),
        Commands::EvmProve {
            params_dir,
            app_circuit_config,
            agg_circuit_config,
            pk_dir,
            input_path,
            proof_path,
            public_input_path,
        } => evm_prove(
            &params_dir,
            &app_circuit_config,
            &agg_circuit_config,
            &pk_dir,
            &input_path,
            &proof_path,
            &public_input_path,
        )
        .unwrap(),
        Commands::Verify {
            params_dir,
            app_circuit_config,
            agg_circuit_config,
            vk_path,
            public_input_path,
            proof_path,
        } => verify(
            &params_dir,
            &app_circuit_config,
            &agg_circuit_config,
            &vk_path,
            &public_input_path,
            &proof_path,
        )
        .unwrap(),
        Commands::GenEvmVerifier {
            params_dir,
            app_circuit_config,
            agg_circuit_config,
            vk_path,
            code_path,
        } => gen_evm_verifier(
            &params_dir,
            &app_circuit_config,
            &agg_circuit_config,
            &vk_path,
            &code_path,
        )
        .unwrap(),
    }
}
