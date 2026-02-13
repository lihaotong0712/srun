use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::PathBuf;

use crate::cli::Cli;
use crate::error::ConfigError;
use crate::http::CertVerification;
use crate::warn;
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(skip)]
    pub bind_addr: Option<IpAddr>,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("username", &self.username)
            .field("password", &"******")
            .field("ip", &self.ip)
            .field("iface", &self.iface)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_ip: Option<String>,
    pub verify_cert: String,
    pub users: Vec<User>,
    pub strict_bind: bool,
    pub enc: String,
    pub n: u32,
    pub r#type: u32,
    pub acid: u32,
    pub double_stack: bool,
    pub os: String,
    pub os_name: String,
    pub retry_count: u32,
    pub retry_delay: u64,
    #[serde(skip)]
    pub cert_verification: CertVerification,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: String::from("http://10.0.0.1"),
            server_ip: None,
            verify_cert: "system".into(),
            users: vec![],
            strict_bind: false,
            enc: String::from("srun_bx1"),
            n: 200,
            r#type: 1,
            acid: 1,
            double_stack: false,
            os: String::from("Linux"),
            os_name: String::from("Linux"),
            retry_count: 10,
            retry_delay: 500,
            #[cfg(feature = "tls")]
            cert_verification: CertVerification::System,
            #[cfg(not(feature = "tls"))]
            cert_verification: CertVerification::None,
        }
    }
}

impl Config {
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).unwrap()
    }

    pub fn from_cli(cli: Cli) -> Self {
        let mut config = Config::default();
        if let Some(config_file) = cli.config {
            let config_content =
                fs::read_to_string(config_file).expect("Failed to read config file");
            config = Config::from_json(&config_content);
        }

        if let Some(server) = cli.server {
            config.server = server;
        }

        if let Some(server_ip) = cli.server_ip {
            config.server_ip = Some(server_ip);
        }

        if let (Some(username), Some(password)) = (cli.username, cli.password) {
            config.users = vec![User {
                username: username,
                password: password,
                ip: cli.ip,
                iface: cli.iface,
                bind_addr: None,
            }];
        }

        if let Some(strict_bind) = cli.strict_bind {
            config.strict_bind = strict_bind;
        }

        if let Some(enc) = cli.enc {
            config.enc = enc;
        }

        if let Some(n) = cli.n {
            config.n = n;
        }

        if let Some(r#type) = cli.r#type {
            config.r#type = r#type;
        }

        if let Some(acid) = cli.acid {
            config.acid = acid;
        }

        if let Some(double_stack) = cli.double_stack {
            config.double_stack = double_stack;
        }

        if let Some(os) = cli.os {
            config.os = os;
        }

        if let Some(os_name) = cli.os_name {
            config.os_name = os_name;
        }

        if let Some(retry_count) = cli.retry_count {
            config.retry_count = retry_count;
        }

        if let Some(retry_delay) = cli.retry_delay {
            config.retry_delay = retry_delay;
        }

        if let Some(verify_cert) = cli.verify_cert {
            config.verify_cert = verify_cert;
        }

        #[cfg(feature = "tls")]
        {
            config.cert_verification = match config.verify_cert.as_str() {
                "skip" => CertVerification::Skip,
                "system" => CertVerification::System,
                path => CertVerification::Custom(PathBuf::from(path)),
            };
        }
        #[cfg(not(feature = "tls"))]
        {
            config.cert_verification = CertVerification::None;
        }

        config
    }

    pub fn check(&mut self) -> Result<(), Box<dyn Error>> {
        if self.users.is_empty() {
            return Err(ConfigError::Validation("No users configured").into());
        }
        for user in &self.users {
            if user.username.is_empty() {
                return Err(ConfigError::Validation("Username cannot be empty").into());
            }
            if user.password.is_empty() {
                return Err(ConfigError::Validation("Password cannot be empty").into());
            }
        }
        let interfaces = if_addrs::get_if_addrs().expect("Failed to get network interfaces");
        let mut interfaces_iter = interfaces.clone().into_iter();

        for user in &mut self.users {
            if let Some(user_iface) = &user.iface {
                let iface = interfaces_iter
                    .find(|iface_info| {
                        iface_info.name == *user_iface
                            && matches!(iface_info.addr, if_addrs::IfAddr::V4(_))
                    })
                    .ok_or_else(|| {
                        ConfigError::Validation("Network interface not found or no IPv4 address")
                    })?;
                let ip = match iface.addr {
                    if_addrs::IfAddr::V4(v4_addr) => v4_addr.ip.to_string(),
                    if_addrs::IfAddr::V6(_) => {
                        return Err(ConfigError::Validation(
                            "Interface does not have IPv4 address",
                        )
                        .into());
                    }
                };
                if let Some(user_ip) = &user.ip
                    && user_ip != &ip
                {
                    warn!(
                        "Warning: The specified IP {} for user {} does not match the IP {} of the specified interface {}, using interface IP",
                        user_ip, user.username, ip, user_iface
                    );
                }
                user.ip = Some(ip.clone());
                user.bind_addr = Some(IpAddr::from_str(&ip)?);
            } else if let Some(user_ip) = &user.ip {
                let ip = IpAddr::from_str(user_ip)?;
                if matches!(ip, IpAddr::V6(_)) {
                    return Err(ConfigError::Validation("IPv6 addresses not supported").into());
                }
                interfaces_iter
                    .find(|iface_info| {
                        iface_info.ip().is_ipv4() && iface_info.ip().to_string() == *user_ip
                    })
                    .ok_or_else(|| {
                        ConfigError::Validation("IP address not found on any interface")
                    })?;
                user.bind_addr = Some(ip);
            }
            if self.strict_bind && user.bind_addr.is_none() {
                return Err(ConfigError::Validation(
                    "IP or Interface required when strict_bind enabled",
                )
                .into());
            }
        }
        Ok(())
    }

    pub fn generate_example_config(path: PathBuf) -> Result<(), Box<dyn Error>> {
        let mut example_config = Config::default();
        example_config.server_ip = Some(String::from("10.0.0.1"));
        #[cfg(feature = "tls")]
        {
            example_config.verify_cert = String::from("system");
        }
        #[cfg(not(feature = "tls"))]
        {
            example_config.verify_cert = String::from("skip");
        }
        example_config.users.push(User {
            username: String::from("your_username"),
            password: String::from("your_password"),
            ip: Some(String::from("your_ipv4_address")),
            iface: None,
            bind_addr: None,
        });
        example_config.users.push(User {
            username: String::from("your_username"),
            password: String::from("your_password"),
            ip: None,
            iface: Some(String::from("your_interface_name")),
            bind_addr: None,
        });
        let json = serde_json::to_string_pretty(&example_config)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
