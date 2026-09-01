use hyper::{server::conn::Http, service::service_fn};
use rust_verusd_rpc_server::auth::AuthState;
use rust_verusd_rpc_server::usage_log::ApiUsageLog;
use rust_verusd_rpc_server::{
    configured_api_keys, handle_localhost_req_with_logging, handle_req_with_logging,
    load_tls_config, BlocklistIdentityCache, RequestLogConfig, RequestPolicy, VerusRPC,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
struct ServerContext {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    request_policy: RequestPolicy,
    blocklist_identity_cache: Arc<BlocklistIdentityCache>,
    auth: Option<Arc<AuthState>>,
    usage_log: Option<Arc<ApiUsageLog>>,
    request_logging: bool,
}

#[tokio::main]
async fn main() {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("Conf"))
        .build()
        .expect("Failed to open configuration file");

    let secrets = config::Config::builder()
        .add_source(config::File::with_name("Secrets"))
        .build()
        .expect("Failed to open configuration file");

    let url = settings
        .get_string("rpc_url")
        .expect("Failed to read 'rpc_url' from configuration");
    let user = secrets
        .get_string("rpc_user")
        .expect("Failed to read 'rpc_user' from configuration");
    let password = secrets
        .get_string("rpc_password")
        .expect("Failed to read 'rpc_password' from configuration");

    let port = settings
        .get::<u16>("server_port")
        .expect("Failed to read 'server_port' from configuration");
    let server_addr = settings
        .get_string("server_addr")
        .expect("Failed to read 'server_addr' from configuration");
    let localhost_http_port = configured_localhost_http_port(&settings)
        .unwrap_or_else(|error| panic!("Invalid localhost HTTP configuration: {error}"));
    let request_logging = settings.get::<bool>("logging").unwrap_or(false);
    if request_logging {
        eprintln!("Verbose request logging enabled.");
    }

    let request_policy = RequestPolicy::from_config(&settings, &secrets)
        .unwrap_or_else(|error| panic!("Invalid request policy configuration: {error}"));
    eprintln!(
        "Request policy loaded ({} whitelisted method(s), {} blocked address(es), {} blocked txid(s), identity-name resolution {}, canonical updateidentity names {}).",
        request_policy.method_whitelist_len(),
        request_policy.address_blocklist_len(),
        request_policy.txid_blocklist_len(),
        if request_policy.resolves_identity_names_for_blocklist() {
            "enabled"
        } else {
            "disabled"
        },
        if request_policy.requires_canonical_identity_leaf_names() {
            "required"
        } else {
            "optional"
        }
    );

    let auth_enabled = settings
        .get::<bool>("auth_enabled")
        .expect("Failed to read required 'auth_enabled' from configuration");
    let configured_keys = configured_api_keys(auth_enabled, &secrets)
        .unwrap_or_else(|error| panic!("Invalid authentication configuration: {error}"));
    let app_ids: Vec<String> = configured_keys
        .as_ref()
        .map(|api_keys| api_keys.keys().cloned().collect())
        .unwrap_or_default();
    let auth: Option<Arc<AuthState>> = configured_keys.map(|api_keys| {
        eprintln!(
            "API key authentication enabled ({} app(s) configured).",
            api_keys.len()
        );
        Arc::new(AuthState::new(api_keys))
    });
    let usage_log: Option<Arc<ApiUsageLog>> = if app_ids.is_empty() {
        None
    } else {
        let usage_log = Arc::new(
            ApiUsageLog::new("logs", app_ids).expect("Failed to initialize API usage logger"),
        );
        eprintln!("API usage log: {}", usage_log.log_path().display());
        Some(usage_log)
    };
    if let Some(usage_log) = &usage_log {
        let usage_log = usage_log.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = usage_log.flush_snapshot() {
                    eprintln!("Failed to update API usage log: {}", err);
                }
            }
        });
    }

    let addr = SocketAddr::new(
        server_addr
            .parse::<IpAddr>()
            .expect("Invalid server_addr in configuration"),
        port,
    );
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind server address");

    let tls_enabled = settings.get::<bool>("tls_enabled").unwrap_or(false);
    let tls_acceptor = if tls_enabled {
        let cert_path = secrets
            .get_string("tls_cert_path")
            .expect("'tls_cert_path' is required when tls_enabled = true");
        let key_path = secrets
            .get_string("tls_key_path")
            .expect("'tls_key_path' is required when tls_enabled = true");
        let tls_config =
            load_tls_config(&cert_path, &key_path).expect("Failed to load TLS certificate/key");
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
    } else {
        None
    };

    let context = ServerContext {
        rpc_url: url,
        rpc_user: user,
        rpc_password: password,
        request_policy,
        blocklist_identity_cache: Arc::new(BlocklistIdentityCache::new()),
        auth,
        usage_log,
        request_logging,
    };

    if let Some(localhost_port) = localhost_http_port {
        let (ipv4_listener, ipv6_listener) = bind_localhost_http(localhost_port)
            .await
            .unwrap_or_else(|error| {
                panic!("Failed to bind localhost HTTP listener on port {localhost_port}: {error}")
            });
        eprintln!(
            "Localhost testing listener: http://127.0.0.1:{localhost_port} and http://[::1]:{localhost_port} (normal authentication and RPC policy remain enabled)."
        );
        tokio::spawn(serve_http_listener(ipv4_listener, context.clone(), true));
        tokio::spawn(serve_http_listener(ipv6_listener, context.clone(), true));
    }

    if let Some(acceptor) = tls_acceptor {
        eprintln!("Listening on https://{}", addr);
        serve_tls_listener(listener, acceptor, context).await;
    } else {
        eprintln!("Listening on http://{}", addr);
        serve_http_listener(listener, context, false).await;
    }
}

fn configured_localhost_http_port(settings: &config::Config) -> Result<Option<u16>, String> {
    match settings.get::<u16>("localhost_http_port") {
        Ok(0) => Err("'localhost_http_port' must be between 1 and 65535".to_string()),
        Ok(port) => Ok(Some(port)),
        Err(config::ConfigError::NotFound(_)) => Ok(None),
        Err(error) => Err(format!(
            "'localhost_http_port' must be an integer between 1 and 65535: {error}"
        )),
    }
}

async fn bind_localhost_http(port: u16) -> std::io::Result<(TcpListener, TcpListener)> {
    let ipv4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let ipv4_listener = TcpListener::bind(ipv4_addr).await?;
    // Port zero is useful for isolated tests. Configuration rejects it, so a
    // real listener always uses the explicitly configured port.
    let selected_port = ipv4_listener.local_addr()?.port();
    let ipv6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), selected_port);
    let ipv6_listener = TcpListener::bind(ipv6_addr).await?;
    Ok((ipv4_listener, ipv6_listener))
}

async fn serve_http_listener(listener: TcpListener, context: ServerContext, localhost_cors: bool) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer_addr)) => {
                if context.request_logging {
                    eprintln!("Accepted TCP connection from {peer_addr}");
                }
                let rpc = rpc_for_connection(&context);
                let auth = context.auth.clone();
                let usage_log = context.usage_log.clone();
                let request_logging = context.request_logging;
                tokio::spawn(async move {
                    if let Err(error) = Http::new()
                        .http1_only(true)
                        .serve_connection(
                            tcp,
                            service_fn(move |req| {
                                let rpc = rpc.clone();
                                let auth = auth.clone();
                                let usage_log = usage_log.clone();
                                async move {
                                    let log_config = request_log_config(request_logging, peer_addr);
                                    if localhost_cors {
                                        handle_localhost_req_with_logging(
                                            req, rpc, auth, usage_log, log_config,
                                        )
                                        .await
                                    } else {
                                        handle_req_with_logging(
                                            req, rpc, auth, usage_log, log_config,
                                        )
                                        .await
                                    }
                                }
                            }),
                        )
                        .await
                    {
                        eprintln!("Connection error: {error}");
                    }
                });
            }
            Err(error) => eprintln!("Accept error: {error}"),
        }
    }
}

async fn serve_tls_listener(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    context: ServerContext,
) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer_addr)) => {
                if context.request_logging {
                    eprintln!("Accepted TCP connection from {peer_addr}");
                }
                let rpc = rpc_for_connection(&context);
                let acceptor = acceptor.clone();
                let auth = context.auth.clone();
                let usage_log = context.usage_log.clone();
                let request_logging = context.request_logging;
                tokio::spawn(async move {
                    match acceptor.accept(tcp).await {
                        Ok(tls) => {
                            if request_logging {
                                eprintln!("TLS handshake completed for {peer_addr}");
                            }
                            if let Err(error) = Http::new()
                                .http1_only(true)
                                .serve_connection(
                                    tls,
                                    service_fn(move |req| {
                                        let log_config =
                                            request_log_config(request_logging, peer_addr);
                                        handle_req_with_logging(
                                            req,
                                            rpc.clone(),
                                            auth.clone(),
                                            usage_log.clone(),
                                            log_config,
                                        )
                                    }),
                                )
                                .await
                            {
                                eprintln!("Connection error: {error}");
                            }
                        }
                        Err(error) => eprintln!("TLS handshake error: {error}"),
                    }
                });
            }
            Err(error) => eprintln!("Accept error: {error}"),
        }
    }
}

fn rpc_for_connection(context: &ServerContext) -> Arc<VerusRPC> {
    Arc::new(
        VerusRPC::new_with_policy_and_blocklist_identity_cache(
            &context.rpc_url,
            &context.rpc_user,
            &context.rpc_password,
            context.request_policy.clone(),
            context.blocklist_identity_cache.clone(),
        )
        .expect("Failed to configure Verus RPC backend URL"),
    )
}

fn request_log_config(request_logging: bool, peer_addr: SocketAddr) -> RequestLogConfig {
    if request_logging {
        RequestLogConfig::enabled_for_peer(peer_addr)
    } else {
        RequestLogConfig::disabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_from_toml(source: &str) -> config::Config {
        config::Config::builder()
            .add_source(config::File::from_str(source, config::FileFormat::Toml))
            .build()
            .unwrap()
    }

    #[test]
    fn localhost_http_port_is_optional() {
        assert_eq!(
            configured_localhost_http_port(&config_from_toml("logging = false")).unwrap(),
            None
        );
    }

    #[test]
    fn localhost_http_port_rejects_zero_and_invalid_values() {
        assert!(
            configured_localhost_http_port(&config_from_toml("localhost_http_port = 0")).is_err()
        );
        assert!(configured_localhost_http_port(&config_from_toml(
            "localhost_http_port = 'invalid'"
        ))
        .is_err());
    }

    #[tokio::test]
    async fn localhost_http_accepts_connections_on_both_loopback_families() {
        let (ipv4_listener, ipv6_listener) = bind_localhost_http(0).await.unwrap();
        let ipv4_addr = ipv4_listener.local_addr().unwrap();
        let ipv6_addr = ipv6_listener.local_addr().unwrap();
        let port = ipv4_addr.port();
        assert_eq!(
            ipv4_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        );
        assert_eq!(
            ipv6_addr,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
        );

        let (ipv4_connection, ipv6_connection) = tokio::join!(
            tokio::net::TcpStream::connect(ipv4_addr),
            tokio::net::TcpStream::connect(ipv6_addr)
        );
        assert!(ipv4_connection.is_ok());
        assert!(ipv6_connection.is_ok());
    }
}
