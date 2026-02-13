use httparse;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

#[cfg(feature = "tls")]
use rustls::client::{ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "tls")]
use std::path::PathBuf;
#[cfg(feature = "tls")]
use std::sync::Arc;

use crate::error::HttpError;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: u8,
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum CertVerification {
    #[cfg(feature = "tls")]
    Skip,
    #[cfg(feature = "tls")]
    System,
    #[cfg(feature = "tls")]
    Custom(#[cfg(feature = "tls")] PathBuf),
    #[cfg(not(feature = "tls"))]
    None,
}

pub struct HttpClient {
    tcp_stream: TcpStream,
    #[cfg(feature = "tls")]
    tls_connection: Option<rustls::ClientConnection>,
    host: String,
    is_https: bool,
}

impl HttpClient {
    pub fn new(
        is_https: bool,
        host: &str,
        port: u16,
        local_addr: Option<SocketAddr>,
        remote_addr: Option<SocketAddr>,
        #[allow(unused_variables)] cert_verification: &CertVerification,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(not(feature = "tls"))]
        if is_https {
            return Err(
                HttpError::Tls("TLS support not compiled in. Rebuild with --features tls").into(),
            );
        }

        let target_addr = if let Some(addr) = remote_addr {
            addr
        } else {
            format!("{}:{}", host, port)
                .to_socket_addrs()?
                .next()
                .ok_or("Failed to resolve hostname")?
        };

        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;

        socket.set_reuse_address(true)?;

        if let Some(local) = local_addr {
            socket.bind(&local.into())?;
        }

        socket.connect(&target_addr.into())?;
        let tcp_stream: TcpStream = socket.into();

        #[cfg(feature = "tls")]
        let tls_connection = if is_https {
            let config = Arc::new(match cert_verification {
                CertVerification::Skip => rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth(),
                CertVerification::Custom(cert_path) => {
                    let mut root_cert_store = rustls::RootCertStore::empty();
                    let cert_file = std::fs::read(&cert_path)?;
                    let cert = rustls::Certificate(cert_file);
                    root_cert_store.add(&cert)?;

                    rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(root_cert_store)
                        .with_no_client_auth()
                }
                CertVerification::System => {
                    let mut root_cert_store = rustls::RootCertStore::empty();
                    for cert in rustls_native_certs::load_native_certs()? {
                        root_cert_store.add(&rustls::Certificate(cert.0))?;
                    }

                    rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(root_cert_store)
                        .with_no_client_auth()
                }
            });

            Some(rustls::ClientConnection::new(config, host.try_into()?)?)
        } else {
            None
        };

        Ok(HttpClient {
            tcp_stream,
            #[cfg(feature = "tls")]
            tls_connection,
            host: host.to_string(),
            is_https,
        })
    }

    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        query: Option<Vec<(&str, &str)>>,
    ) -> Result<HttpResponse, Box<dyn Error>> {
        let path_with_query = if let Some(params) = query {
            let query_string = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(params)
                .finish();
            format!("{}?{}", path, query_string)
        } else {
            path.to_string()
        };
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            method, path_with_query, self.host
        );

        if self.is_https {
            #[cfg(feature = "tls")]
            {
                if let Some(ref mut conn) = self.tls_connection {
                    let mut tls_stream = rustls::Stream::new(conn, &mut self.tcp_stream);
                    tls_stream.write_all(request.as_bytes())?;
                    Self::read_response(&mut tls_stream)
                } else {
                    Err(HttpError::Tls("HTTPS connection not established").into())
                }
            }
            #[cfg(not(feature = "tls"))]
            {
                Err(HttpError::Tls("TLS support not compiled in").into())
            }
        } else {
            self.tcp_stream.write_all(request.as_bytes())?;
            Self::read_response(&mut self.tcp_stream)
        }
    }

    fn read_response<R: Read>(stream: &mut R) -> Result<HttpResponse, Box<dyn Error>> {
        let mut buffer = Vec::new();
        let mut temp_buf = [0; 8192];

        // 使用 httparse 增量解析响应头
        loop {
            let bytes_read = stream.read(&mut temp_buf)?;
            if bytes_read == 0 {
                return Err(
                    HttpError::Protocol("Connection closed before headers complete").into(),
                );
            }

            buffer.extend_from_slice(&temp_buf[..bytes_read]);

            // 尝试解析响应头
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut headers);

            match response.parse(&buffer)? {
                httparse::Status::Complete(n) => {
                    // 解析成功，n 是头部的字节数

                    // 提取响应信息
                    let version = response.version.unwrap_or(1);
                    let status_code = response.code.unwrap_or(200);
                    let reason = response.reason.unwrap_or("OK").to_string();

                    // 转换 headers
                    let parsed_headers: Vec<(String, String)> = response
                        .headers
                        .iter()
                        .map(|h| {
                            (
                                h.name.to_string(),
                                String::from_utf8_lossy(h.value).into_owned(),
                            )
                        })
                        .collect();

                    // 获取 Content-Length
                    let content_length = parsed_headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.parse::<usize>().ok())
                        .unwrap_or(0);

                    // 读取剩余的 body
                    let mut body_read = buffer.len() - n;
                    while body_read < content_length {
                        let bytes_read = stream.read(&mut temp_buf)?;
                        if bytes_read == 0 {
                            break;
                        }
                        buffer.extend_from_slice(&temp_buf[..bytes_read]);
                        body_read += bytes_read;
                    }

                    // 提取 body
                    let body = if buffer.len() > n {
                        buffer[n..].to_vec()
                    } else {
                        Vec::new()
                    };

                    return Ok(HttpResponse {
                        version,
                        status_code,
                        reason,
                        headers: parsed_headers,
                        body,
                    });
                }
                httparse::Status::Partial => {
                    // 需要更多数据，继续读取
                    continue;
                }
            }
        }
    }
}

#[cfg(feature = "tls")]
struct NoVerifier;

#[cfg(feature = "tls")]
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &rustls::Certificate,
        _: &[rustls::Certificate],
        _: &rustls::ServerName,
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: std::time::SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = HttpClient::new(
            false, // HTTP
            "httpbin.org",
            80,
            Some("192.168.1.12:0".parse()?),
            None,
            #[cfg(feature = "tls")]
            &CertVerification::System,
            #[cfg(not(feature = "tls"))]
            &CertVerification::None,
        )?;

        let response = client.request("GET", "/get", None)?;
        let response_str = String::from_utf8_lossy(&response.body);

        println!("HTTP GET Response: {}", response_str);
        println!("Status: {}", response.status_code);
        assert!(response.status_code == 200);

        let response = client.request("POST", "/post", None)?;
        let response_str = String::from_utf8_lossy(&response.body);

        println!("HTTP POST Response: {}", response_str);
        println!("Status: {}", response.status_code);
        assert!(response.status_code == 200);
        Ok(())
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_https() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = HttpClient::new(
            true, // HTTPS
            "httpbin.org",
            443,
            Some("192.168.1.12:0".parse()?),
            None,
            &CertVerification::System, // 使用系统证书验证
        )?;

        let response = client.request("GET", "/get", None)?;
        let response_str = String::from_utf8_lossy(&response.body);

        println!("HTTPS GET Response: {}", response_str);
        println!("Status: {}", response.status_code);
        assert!(response.status_code == 200);

        let response = client.request("POST", "/post", None)?;
        let response_str = String::from_utf8_lossy(&response.body);

        println!("HTTPS POST Response: {}", response_str);
        println!("Status: {}", response.status_code);
        assert!(response.status_code == 200);

        Ok(())
    }

    #[test]
    #[cfg(feature = "tls")]
    fn test_https_skip_cert_verification() -> Result<(), Box<dyn std::error::Error>> {
        let mut client = HttpClient::new(
            true, // HTTPS
            "httpbin.org",
            443,
            Some("192.168.1.12:0".parse()?),
            None,
            &CertVerification::Skip, // 跳过证书验证
        )?;

        let response = client.request("GET", "/get", None)?;
        let response_str = String::from_utf8_lossy(&response.body);

        println!("HTTPS GET (Skip Cert) Response: {}", response_str);
        println!("Status: {}", response.status_code);
        assert!(response.status_code == 200);

        Ok(())
    }
}
