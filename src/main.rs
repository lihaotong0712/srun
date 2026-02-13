use clap::Parser;
use if_addrs::IfAddr;
use std::error::Error;

use crate::cli::{Cli, Commands};
use crate::config::Config;
use crate::srun::SrunClient;

mod cli;
mod config;
mod error;
mod http;
mod log;
mod srun;
mod xencode;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let cmd = &cli.command.clone();
    let force = cli.force;
    let mut config = Config::from_cli(cli);
    match cmd {
        Commands::GenConfig { file } => {
            info!("Generating default configuration file to {:?}", file);
            Config::generate_example_config(file.clone())?;
        }
        Commands::Interfaces => {
            info!("Listing network interfaces:");
            let interfaces = if_addrs::get_if_addrs().expect("Failed to get network interfaces");

            for iface in &interfaces {
                if let IfAddr::V4(addr) = &iface.addr {
                    println!("(IPv4) {}: {}", iface.name, addr.ip);
                }
            }
            for iface in &interfaces {
                if let IfAddr::V6(addr) = &iface.addr {
                    println!("(IPv6) {}: {}", iface.name, addr.ip);
                }
            }
        }
        Commands::Login => {
            check_config(&mut config)?;
            for user in &config.users {
                info!("Logging in user: {}", user.username);
                let mut client = SrunClient::new(&config, user.clone())?;
                let status = check_status(&mut client)?;
                if !status || force {
                    client.login()?;
                }
            }
        }
        Commands::Logout => {
            check_config(&mut config)?;
            for user in &config.users {
                info!("Logging out user: {}", user.username);
                let mut client = SrunClient::new(&config, user.clone())?;
                let status = check_status(&mut client)?;
                if status || force {
                    client.logout()?;
                }
            }
        }
    }
    Ok(())
}

fn check_config(config: &mut Config) -> Result<(), Box<dyn Error>> {
    config.check()?;
    println!("{:#?}", config);
    Ok(())
}

fn check_status(client: &mut SrunClient) -> Result<bool, Box<dyn Error>> {
    let (status, online_info) = client.check_status()?;
    if status {
        info!(
            "Already logged in at {} ({}) as {}.",
            online_info.online_ip,
            online_info.user_mac.unwrap(),
            online_info.user_name.unwrap()
        );
        info!(
            "Bytes in: {} M, bytes out: {} M. All bytes: {} M. Sum bytes: {} M, Sum Hours: {} H",
            online_info.bytes_in.unwrap() / 1048576,
            online_info.bytes_out.unwrap() / 1048576,
            (online_info.all_bytes.unwrap()) / 1048576,
            online_info.sum_bytes.unwrap() / 1048576,
            online_info.sum_seconds.unwrap() / 3600
        );
        info!("Online since: {}", online_info.add_time.unwrap());
        debug!("Srun Version: {}", online_info.sysver.unwrap());
    } else {
        info!(
            "Not logged in. Current online IP: {}",
            online_info.online_ip
        );
    }
    Ok(status)
}
