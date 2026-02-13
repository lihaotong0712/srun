#![allow(dead_code)]
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum SrunError {
    Challenge(&'static str),
    Login(&'static str),
    Logout(&'static str),
    Config(&'static str),
    Network(&'static str),
}

impl fmt::Display for SrunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrunError::Challenge(msg) => write!(f, "Challenge error: {}", msg),
            SrunError::Login(msg) => write!(f, "Login error: {}", msg),
            SrunError::Logout(msg) => write!(f, "Logout error: {}", msg),
            SrunError::Config(msg) => write!(f, "Config error: {}", msg),
            SrunError::Network(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl Error for SrunError {}

#[derive(Debug)]
pub enum HttpError {
    Connection(&'static str),
    Protocol(&'static str),
    Tls(&'static str),
    Parse(&'static str),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Connection(msg) => write!(f, "Connection error: {}", msg),
            HttpError::Protocol(msg) => write!(f, "HTTP protocol error: {}", msg),
            HttpError::Tls(msg) => write!(f, "TLS error: {}", msg),
            HttpError::Parse(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl Error for HttpError {}

#[derive(Debug)]
pub enum ConfigError {
    Validation(&'static str),
    Io(&'static str),
    Parse(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Validation(msg) => write!(f, "Config validation error: {}", msg),
            ConfigError::Io(msg) => write!(f, "Config file error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "Config parse error: {}", msg),
        }
    }
}

impl Error for ConfigError {}
