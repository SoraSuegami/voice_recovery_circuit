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
        #[arg(short, long)]
        params_path: String,
        /// circuit configure file
        #[arg(short, long)]
        circuit_config: String,
        /// proving key file path
        #[arg(long)]
        pk_path: String,
        /// verifying key file path
        #[arg(long)]
        vk_path: String,
    },
    Prove {
        /// setup parameter file
        #[arg(short, long)]
        params_path: String,
        /// circuit configure file
        #[arg(short, long)]
        circuit_config: String,
        /// proving key file path
        #[arg(long)]
        pk_path: String,
        /// input file path
        #[arg(long)]
        input_path: String,
        /// proof file path
        #[arg(long)]
        proof_path: String,
        /// public input file path
        #[arg(long)]
        public_input_path: String,
    },
    EvmProve {
        /// setup parameter file
        #[arg(short, long)]
        params_path: String,
        /// circuit configure file
        #[arg(short, long)]
        circuit_config: String,
        /// proving key file path
        #[arg(long)]
        pk_path: String,
        /// input file path
        #[arg(long)]
        input_path: String,
        /// proof file path
        #[arg(long)]
        proof_path: String,
        /// public input file path
        #[arg(long)]
        public_input_path: String,
    },
    Verify {
        /// setup parameter file
        #[arg(short, long)]
        params_path: String,
        /// circuit configure file
        #[arg(short, long)]
        circuit_config: String,
        /// verifying key file path
        #[arg(long)]
        vk_path: String,
        /// public input file path
        #[arg(long)]
        public_input_path: String,
        /// proof file path
        #[arg(long)]
        proof_path: String,
    },
    GenEvmVerifier {
        /// setup parameter file
        #[arg(short, long)]
        params_path: String,
        /// circuit configure file
        #[arg(short, long)]
        circuit_config: String,
        /// verifying key file path
        #[arg(long)]
        vk_path: String,
        /// verifier code path
        #[arg(long)]
        code_path: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenParams { k, params_path } => gen_params(&params_path, k).unwrap(),
        Commands::GenKeys {
            params_path,
            circuit_config,
            pk_path,
            vk_path,
        } => gen_keys(&params_path, &circuit_config, &pk_path, &vk_path).unwrap(),
        Commands::Prove {
            params_path,
            circuit_config,
            pk_path,
            input_path,
            proof_path,
            public_input_path,
        } => prove(
            &params_path,
            &circuit_config,
            &pk_path,
            &input_path,
            &proof_path,
            &public_input_path,
        )
        .unwrap(),
        Commands::EvmProve {
            params_path,
            circuit_config,
            pk_path,
            input_path,
            proof_path,
            public_input_path,
        } => evm_prove(
            &params_path,
            &circuit_config,
            &pk_path,
            &input_path,
            &proof_path,
            &public_input_path,
        )
        .unwrap(),
        Commands::Verify {
            params_path,
            circuit_config,
            vk_path,
            public_input_path,
            proof_path,
        } => verify(
            &params_path,
            &circuit_config,
            &vk_path,
            &public_input_path,
            &proof_path,
        )
        .unwrap(),
        Commands::GenEvmVerifier {
            params_path,
            circuit_config,
            vk_path,
            code_path,
        } => gen_evm_verifier(&params_path, &circuit_config, &vk_path, &code_path).unwrap(),
    }
}
