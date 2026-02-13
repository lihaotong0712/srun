use hmac::{Hmac, Mac};
use md5::Md5;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::{
    net::IpAddr,
    str::FromStr,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::{ParseError, Url};

use crate::error::SrunError;

use crate::config::Config;
use crate::config::User;
use crate::debug;
use crate::http::HttpClient;
use crate::info;
use crate::xencode;

const PATH_GET_CHALLENGE: &str = "/cgi-bin/get_challenge";
const PATH_PORTAL: &str = "/cgi-bin/srun_portal";
const PATH_INFO: &str = "/cgi-bin/rad_user_info";

pub struct SrunClient {
    config: Config,
    user: User,
    client: HttpClient,
}

impl SrunClient {
    pub fn new(config: &Config, user: User) -> Result<Self, Box<dyn Error>> {
        let url = Url::parse(&config.server)?;
        let is_https = url.scheme() == "https";
        let host = url.host_str().ok_or(ParseError::EmptyHost)?;
        let port = url.port().unwrap_or(if is_https { 443 } else { 80 });
        let remote_addr = if let Some(server_ip) = config.server_ip.clone() {
            Some(SocketAddr::new(IpAddr::from_str(&server_ip)?, port))
        } else {
            None
        };

        let local_addr = if config.strict_bind
            && let Some(local_ip) = user.bind_addr
        {
            Some(SocketAddr::new(local_ip, 0))
        } else {
            None
        };

        let client = HttpClient::new(
            is_https,
            host,
            port,
            local_addr,
            remote_addr,
            &config.cert_verification,
        )?;

        Ok(Self {
            config: config.clone(),
            user,
            client,
        })
    }

    fn jsonp(
        &mut self,
        path: &str,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let jsonp = format!("jsonp_{}", timestamp);
        let callback = ("callback", jsonp.as_str());
        let query = if let Some(mut params) = query {
            params.push(callback);
            params
        } else {
            vec![callback]
        };
        let response = self.client.request("GET", path, Some(query))?;
        Ok(response.body[jsonp.len() + 1..response.body.len() - 1].to_vec())
    }

    pub fn check_status(&mut self) -> Result<(bool, InfoResponse), Box<dyn Error>> {
        let response_data = self.jsonp(PATH_INFO, None)?;
        let online_info: InfoResponse = serde_json::from_slice(&response_data)?;
        debug!("{:#?}", online_info);
        if let Some(local_ip) = self.user.bind_addr {
            Ok((
                online_info.error == "ok" && online_info.online_ip == local_ip.to_string(),
                online_info,
            ))
        } else {
            self.user.bind_addr = Some(Ipv4Addr::from_str(&online_info.online_ip)?.into());
            Ok((online_info.error == "ok", online_info))
        }
    }

    fn t() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }

    fn get_challenge(&mut self, ip: &str) -> Result<String, Box<dyn Error>> {
        info!("Using online IP: {}", ip);
        let username = self.user.username.clone();
        let t = Self::t();
        let query: Vec<(&str, &str)> = vec![("username", &username), ("ip", ip), ("_", &t)];
        let resp = self.jsonp(PATH_GET_CHALLENGE, Some(query))?;
        let challenge_resp: ChallengeResponse = serde_json::from_slice(&resp)?;
        debug!("{:#?}", challenge_resp);
        if let Some(challenge) = challenge_resp.challenge {
            Ok(challenge)
        } else {
            Err(SrunError::Challenge("Server returned no challenge token").into())
        }
    }

    fn do_login(&mut self, ip: String) -> Result<PortalResponse, Box<dyn Error>> {
        let challenge = self.get_challenge(&ip)?;
        let info = xencode::param_i(
            &self.user.username,
            &self.user.password,
            &ip,
            self.config.acid as i32,
            // &self.config.enc,
            &challenge,
        );
        let hmd5 = {
            let mut mac = Hmac::<Md5>::new_from_slice(challenge.as_bytes())?;
            mac.update(self.user.password.as_bytes());
            let result = mac.finalize();
            format!("{:x}", result.into_bytes())
        };
        let check_sum = {
            let check_sum = [
                "",
                &self.user.username,
                &hmd5,
                &self.config.acid.to_string(),
                &ip,
                &self.config.n.to_string(),
                &self.config.r#type.to_string(),
                &info,
            ]
            .join(&challenge);
            let mut sha1_hasher = Sha1::new();
            sha1_hasher.update(check_sum);
            format!("{:x}", sha1_hasher.finalize())
        };
        debug!("Challenge: {}", challenge);
        debug!("HMD5: {}", hmd5);
        debug!("Info: {}", info);
        debug!("CheckSum: {}", check_sum);
        let username = self.user.username.clone();
        let password = format!("{{MD5}}{}", hmd5);
        let acid = self.config.acid.to_string();
        let n = self.config.n.to_string();
        let r#type = self.config.r#type.to_string();
        let os = self.config.os.clone();
        let os_name = self.config.os_name.clone();
        let double_stack = self.config.double_stack.to_string();
        let t = Self::t();

        let query = vec![
            ("action", "login"),
            ("username", &username),
            ("password", &password),
            ("ip", &ip),
            ("ac_id", &acid),
            ("n", &n),
            ("type", &r#type),
            ("os", &os),
            ("name", &os_name),
            ("double_stack", &double_stack),
            ("info", &info),
            ("chksum", &check_sum),
            ("_", &t),
        ];

        let resp = self.jsonp(PATH_PORTAL, Some(query))?;
        let portal_resp: PortalResponse = serde_json::from_slice(&resp)?;
        info!(
            "PortalResponse: res: {}, error: {}, client_ip: {}, online_ip: {}",
            portal_resp.res, portal_resp.error, portal_resp.client_ip, portal_resp.online_ip
        );
        debug!("{:#?}", portal_resp);
        Ok(portal_resp)
    }

    fn do_logout(&mut self, ip: String) -> Result<PortalResponse, Box<dyn Error>> {
        let username = self.user.username.clone();
        let acid = self.config.acid.to_string();
        let t = Self::t();

        let query = vec![
            ("action", "logout"),
            ("username", &username),
            ("ip", &ip),
            ("ac_id", &acid),
            ("_", &t),
        ];

        let resp = self.jsonp(PATH_PORTAL, Some(query))?;
        let portal_resp: PortalResponse = serde_json::from_slice(&resp)?;
        info!(
            "PortalResponse: res: {}, error: {}, client_ip: {}, online_ip: {}",
            portal_resp.res, portal_resp.error, portal_resp.client_ip, portal_resp.online_ip
        );
        debug!("{:#?}", portal_resp);
        Ok(portal_resp)
    }

    pub fn login(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ip) = self.user.bind_addr {
            let ip = ip.to_string();
            for i in 1..=self.config.retry_count {
                info!("Login attempt {}/{}", i, self.config.retry_count);
                let resp = self.do_login(ip.clone());
                match resp {
                    Ok(resp) => {
                        if resp.res == "ok" && resp.error == "ok" {
                            info!("Login successful: {}", resp.suc_msg);
                            return Ok(());
                        } else {
                            info!("Login failed: {}", resp.error);
                        }
                    }
                    Err(e) => {
                        info!("Login error: {}", e);
                    }
                }
                thread::sleep(Duration::from_millis(self.config.retry_delay));
            }
            Err(SrunError::Login("Exceeded maximum retry attempts").into())
        } else {
            Err(SrunError::Config("No IP address configured").into())
        }
    }

    pub fn logout(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(ip) = self.user.bind_addr {
            let ip = ip.to_string();
            info!("Logout.");
            let resp = self.do_logout(ip.clone());
            match resp {
                Ok(resp) => {
                    if resp.res == "ok" && resp.error == "ok" {
                        info!("Logout successful: {}", resp.suc_msg);
                        Ok(())
                    } else {
                        info!("Logout failed: {}", resp.error);
                        Err(SrunError::Logout("Server rejected logout request").into())
                    }
                }
                Err(e) => {
                    info!("Logout error: {}", e);
                    Err(SrunError::Network("Failed to communicate with server").into())
                }
            }
        } else {
            Err(SrunError::Config("No IP address configured").into())
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
struct ChallengeResponse {
    challenge: Option<String>,
    client_ip: String,
    ecode: ECode,
    error: String,
    error_msg: String,
    expire: Option<String>,
    online_ip: String,
    res: String,
    srun_ver: String,
    st: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct InfoResponse {
    pub online_ip: String,
    pub error: String,

    #[serde(rename = "ServerFlag")]
    pub server_flag: Option<u32>,
    pub add_time: Option<u32>,
    pub all_bytes: Option<u64>,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    pub checkout_date: Option<u32>,
    pub domain: Option<String>,
    pub keepalive_time: Option<u32>,
    pub real_name: Option<String>,
    pub remain_seconds: Option<u32>,
    pub sum_bytes: Option<u64>,
    pub sum_seconds: Option<u32>,
    pub sysver: Option<String>,
    pub user_balance: Option<f64>,
    pub user_charge: Option<f64>,
    pub user_mac: Option<String>,
    pub user_name: Option<String>,
    pub wallet_balance: Option<f64>,

    pub client_ip: Option<String>,
    pub ecode: Option<u32>,
    pub error_msg: Option<String>,
    pub res: Option<String>,
    pub srun_ver: Option<String>,
    pub st: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PortalResponse {
    #[serde(rename = "ServerFlag")]
    pub server_flag: i32,
    #[serde(rename = "ServicesIntfServerIP")]
    pub services_intf_server_ip: String,
    #[serde(rename = "ServicesIntfServerPort")]
    pub services_intf_server_port: String,
    pub access_token: String,
    pub checkout_date: u64,
    pub ecode: ECode,
    pub error: String,
    pub error_msg: String,
    pub client_ip: String,
    pub online_ip: String,
    pub real_name: String,
    pub remain_flux: i32,
    pub remain_times: i32,
    pub res: String,
    pub srun_ver: String,
    pub suc_msg: String,
    pub sysver: String,
    pub username: String,
    pub wallet_balance: i32,
    pub st: u64,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum ECode {
    I(i32),
    S(String),
}

impl Default for ECode {
    fn default() -> Self {
        Self::I(0)
    }
}
