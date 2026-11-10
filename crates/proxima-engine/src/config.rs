use std::env;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamTlsMode {
    Disable,
    VerifyFull,
}

impl UpstreamTlsMode {
    fn parse(value: &str) -> io::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "disable" => Ok(Self::Disable),
            "verify-full" => Ok(Self::VerifyFull),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid PROXIMA_UPSTREAM_TLS_MODE: {other}; expected disable or verify-full"
                ),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub upstream_addr: String,
    pub tenant_signing_key: Option<String>,
    pub tenant_role_prefix: String,
    pub upstream_connect_timeout: Duration,
    pub max_connections: usize,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
    pub tls_handshake_timeout: Duration,
    pub require_client_tls: bool,
    pub upstream_tls_mode: UpstreamTlsMode,
    pub upstream_tls_ca_file: Option<String>,
    pub upstream_tls_server_name: Option<String>,
    pub upstream_tls_handshake_timeout: Duration,
    pub dashboard_enabled: bool,
    pub dashboard_listen_addr: SocketAddr,
}

impl Config {
    pub fn from_env() -> io::Result<Self> {
        let listen_addr = env::var("PROXIMA_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:6432".to_string())
            .parse()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid PROXIMA_LISTEN_ADDR: {error}"),
                )
            })?;

        let upstream_addr =
            env::var("PROXIMA_UPSTREAM_ADDR").unwrap_or_else(|_| "127.0.0.1:5432".to_string());
        if upstream_addr.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_UPSTREAM_ADDR cannot be empty",
            ));
        }

        let tenant_role_prefix = env::var("PROXIMA_TENANT_ROLE_PREFIX")
            .unwrap_or_else(|_| "proxima_tenant_".to_string());
        if tenant_role_prefix.is_empty()
            || !tenant_role_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_TENANT_ROLE_PREFIX must contain only ASCII letters, digits, and underscores",
            ));
        }

        let tenant_signing_key_value = match env::var("PROXIMA_TENANT_SIGNING_KEY_FILE") {
            Ok(path) => Some(std::fs::read_to_string(path)?.trim().to_owned()),
            Err(_) => env::var("PROXIMA_TENANT_SIGNING_KEY").ok(),
        };
        let tenant_signing_key = match tenant_signing_key_value {
            Some(value) if value.trim().is_empty() => None,
            Some(value) if value.len() < 32 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PROXIMA_TENANT_SIGNING_KEY or its secret file must contain at least 32 bytes",
                ))
            }
            Some(value) => Some(value),
            None => None,
        };

        let upstream_connect_timeout_ms = env::var("PROXIMA_UPSTREAM_CONNECT_TIMEOUT_MS")
            .unwrap_or_else(|_| "10000".to_string())
            .parse::<u64>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid PROXIMA_UPSTREAM_CONNECT_TIMEOUT_MS: {error}"),
                )
            })?;
        if upstream_connect_timeout_ms == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_UPSTREAM_CONNECT_TIMEOUT_MS must be greater than zero",
            ));
        }

        let max_connections = env::var("PROXIMA_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "1024".to_string())
            .parse::<usize>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid PROXIMA_MAX_CONNECTIONS: {error}"),
                )
            })?;
        if max_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_MAX_CONNECTIONS must be greater than zero",
            ));
        }

        let tls_cert_file = non_empty_env("PROXIMA_TLS_CERT_FILE");
        let tls_key_file = non_empty_env("PROXIMA_TLS_KEY_FILE");
        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_TLS_CERT_FILE and PROXIMA_TLS_KEY_FILE must be configured together",
            ));
        }

        let require_client_tls = parse_bool("PROXIMA_TLS_REQUIRE_CLIENT", false)?;
        if require_client_tls && tls_cert_file.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_TLS_REQUIRE_CLIENT requires a TLS certificate and key",
            ));
        }

        let tls_handshake_timeout = duration_ms("PROXIMA_TLS_HANDSHAKE_TIMEOUT_MS", 10000)?;
        let upstream_tls_mode = UpstreamTlsMode::parse(
            &env::var("PROXIMA_UPSTREAM_TLS_MODE").unwrap_or_else(|_| "disable".to_string()),
        )?;
        let upstream_tls_ca_file = non_empty_env("PROXIMA_UPSTREAM_TLS_CA_FILE");
        let upstream_tls_server_name = non_empty_env("PROXIMA_UPSTREAM_TLS_SERVER_NAME");
        if upstream_tls_mode != UpstreamTlsMode::Disable && upstream_tls_ca_file.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_UPSTREAM_TLS_CA_FILE is required when upstream TLS is enabled",
            ));
        }
        if upstream_tls_mode == UpstreamTlsMode::VerifyFull && upstream_tls_server_name.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXIMA_UPSTREAM_TLS_SERVER_NAME is required for verify-full",
            ));
        }

        let upstream_tls_handshake_timeout =
            duration_ms("PROXIMA_UPSTREAM_TLS_HANDSHAKE_TIMEOUT_MS", 10000)?;
        let dashboard_enabled = parse_bool("PROXIMA_DASHBOARD_ENABLED", true)?;
        let dashboard_listen_addr = env::var("PROXIMA_DASHBOARD_LISTEN_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9080".to_string())
            .parse()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid PROXIMA_DASHBOARD_LISTEN_ADDR: {error}"),
                )
            })?;

        Ok(Self {
            listen_addr,
            upstream_addr,
            tenant_signing_key,
            tenant_role_prefix,
            upstream_connect_timeout: Duration::from_millis(upstream_connect_timeout_ms),
            max_connections,
            tls_cert_file,
            tls_key_file,
            tls_handshake_timeout,
            require_client_tls,
            upstream_tls_mode,
            upstream_tls_ca_file,
            upstream_tls_server_name,
            upstream_tls_handshake_timeout,
            dashboard_enabled,
            dashboard_listen_addr,
        })
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn parse_bool(name: &str, default: bool) -> io::Result<bool> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {name}: {other}"),
            )),
        },
        Err(_) => Ok(default),
    }
}

fn duration_ms(name: &str, default: u64) -> io::Result<Duration> {
    let value = env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse::<u64>()
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid {name}: {error}"),
            )
        })?;
    if value == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be greater than zero"),
        ));
    }
    Ok(Duration::from_millis(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn defaults_are_valid() {
        for name in [
            "PROXIMA_LISTEN_ADDR",
            "PROXIMA_UPSTREAM_ADDR",
            "PROXIMA_TENANT_SIGNING_KEY",
            "PROXIMA_TENANT_SIGNING_KEY_FILE",
            "PROXIMA_UPSTREAM_CONNECT_TIMEOUT_MS",
            "PROXIMA_MAX_CONNECTIONS",
            "PROXIMA_TLS_CERT_FILE",
            "PROXIMA_TLS_KEY_FILE",
            "PROXIMA_TLS_REQUIRE_CLIENT",
            "PROXIMA_UPSTREAM_TLS_MODE",
            "PROXIMA_UPSTREAM_TLS_CA_FILE",
            "PROXIMA_UPSTREAM_TLS_SERVER_NAME",
            "PROXIMA_DASHBOARD_ENABLED",
            "PROXIMA_DASHBOARD_LISTEN_ADDR",
            "PROXIMA_TLS_HANDSHAKE_TIMEOUT_MS",
            "PROXIMA_UPSTREAM_TLS_HANDSHAKE_TIMEOUT_MS",
        ] {
            std::env::remove_var(name);
        }

        let config = Config::from_env().unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:6432".parse().unwrap());
        assert_eq!(config.upstream_addr, "127.0.0.1:5432");
        assert_eq!(config.tenant_signing_key, None);
        assert_eq!(config.tenant_role_prefix, "proxima_tenant_");
        assert_eq!(config.upstream_connect_timeout, Duration::from_secs(10));
        assert_eq!(config.max_connections, 1024);
        assert_eq!(config.tls_cert_file, None);
        assert!(!config.require_client_tls);
        assert_eq!(config.upstream_tls_mode, UpstreamTlsMode::Disable);
        assert!(config.dashboard_enabled);
    }

    #[test]
    #[serial]
    fn tls_cert_and_key_are_a_pair() {
        std::env::set_var("PROXIMA_TLS_CERT_FILE", "/tmp/cert.pem");
        std::env::remove_var("PROXIMA_TLS_KEY_FILE");
        let error = Config::from_env().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        std::env::remove_var("PROXIMA_TLS_CERT_FILE");
    }

    #[test]
    #[serial]
    fn upstream_verify_full_requires_server_name() {
        std::env::set_var("PROXIMA_UPSTREAM_TLS_MODE", "verify-full");
        std::env::set_var("PROXIMA_UPSTREAM_TLS_CA_FILE", "/tmp/ca.pem");
        std::env::remove_var("PROXIMA_UPSTREAM_TLS_SERVER_NAME");
        let error = Config::from_env().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        std::env::remove_var("PROXIMA_UPSTREAM_TLS_MODE");
        std::env::remove_var("PROXIMA_UPSTREAM_TLS_CA_FILE");
    }
}
