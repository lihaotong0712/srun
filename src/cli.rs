use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Deserialize, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    #[serde(skip)]
    pub command: Commands,

    /// Config file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Srun Auth Server, default is "http://10.0.0.1/"
    #[arg(short, long, global = true)]
    pub server: Option<String>,

    /// Srun Auth Server IP, default is None (resolve from dns)
    #[arg(long, global = true)]
    pub server_ip: Option<String>,

    /// Force login or logout even if already in desired state, default is false
    #[arg(short, long, global = true, default_value_t = false)]
    pub force: bool,

    /// Certificate verification mode: skip, system (default), or path to custom CA cert
    #[arg(long, global = true)]
    pub verify_cert: Option<String>,

    /// Username
    #[arg(short, long, global = true)]
    pub username: Option<String>,

    /// Password
    #[arg(short, long, global = true)]
    pub password: Option<String>,

    /// IP address
    #[arg(long, global = true)]
    pub ip: Option<String>,

    /// Network interface
    #[arg(long, global = true)]
    pub iface: Option<String>,

    /// Enable strict bind, default is false
    #[arg(long, global = true)]
    pub strict_bind: Option<bool>,

    /// Srun Param - Srun enc parameter, default is "srun_bx1"
    #[arg(long, global = true)]
    pub enc: Option<String>,

    /// Srun Param - Srun n parameter, default is 200
    #[arg(long, global = true)]
    pub n: Option<u32>,

    /// Srun Param - Srun type parameter, default is 1
    #[arg(long, global = true)]
    pub r#type: Option<u32>,

    /// Srun Param - "Srun ac_id parameter, default is 1
    #[arg(long, global = true)]
    pub acid: Option<u32>,

    /// Srun Param - Enable double stack, default is false
    #[arg(long, global = true)]
    pub double_stack: Option<bool>,

    /// Srun Param - Operating system, default is "Linux"
    #[arg(long, global = true)]
    pub os: Option<String>,

    /// Srun Param - Operating system name, default is "Linux"
    #[arg(long, global = true)]
    pub os_name: Option<String>,

    /// Retry count, default is 10
    #[arg(long, global = true)]
    pub retry_count: Option<u32>,

    /// Retry interval in milliseconds, default is 500
    #[arg(long, global = true)]
    pub retry_delay: Option<u64>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Login,
    Logout,
    GenConfig {
        #[arg(long, default_value = "./config.json")]
        file: PathBuf,
    },
    Interfaces,
}

impl Default for Commands {
    fn default() -> Self {
        Commands::Interfaces
    }
}
