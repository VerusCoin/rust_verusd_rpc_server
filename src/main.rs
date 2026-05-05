use hyper::{server::conn::Http, service::service_fn};
use rust_verusd_rpc_server::auth::AuthState;
use rust_verusd_rpc_server::usage_log::ApiUsageLog;
use rust_verusd_rpc_server::{
    handle_req_with_logging, load_tls_config, RequestLogConfig, VerusRPC,
};
use std::{collections::HashMap, sync::Arc};
use tokio::net::TcpListener;

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
    let request_logging = settings.get::<bool>("logging").unwrap_or(false);
    if request_logging {
        eprintln!("Verbose request logging enabled.");
    }

    let rpc = Arc::new(VerusRPC::new(&url, &user, &password).unwrap());

    // Load optional [api_keys] table from Secrets. If absent or empty, auth is disabled.
    let api_keys: HashMap<String, String> = secrets
        .get::<HashMap<String, String>>("api_keys")
        .unwrap_or_default();
    let app_ids: Vec<String> = api_keys.keys().cloned().collect();
    let auth: Option<Arc<AuthState>> = if api_keys.is_empty() {
        None
    } else {
        eprintln!(
            "API key authentication enabled ({} app(s) configured).",
            api_keys.len()
        );
        Some(Arc::new(AuthState::new(api_keys)))
    };
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

    let addr: std::net::SocketAddr = (
        server_addr
            .parse::<std::net::IpAddr>()
            .expect("Invalid server_addr in configuration"),
        port,
    )
        .into();

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind server address");

    let tls_enabled = settings.get::<bool>("tls_enabled").unwrap_or(false);

    if tls_enabled {
        let cert_path = secrets
            .get_string("tls_cert_path")
            .expect("'tls_cert_path' is required when tls_enabled = true");
        let key_path = secrets
            .get_string("tls_key_path")
            .expect("'tls_key_path' is required when tls_enabled = true");

        let tls_config =
            load_tls_config(&cert_path, &key_path).expect("Failed to load TLS certificate/key");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        eprintln!("Listening on https://{}", addr);
        loop {
            match listener.accept().await {
                Ok((tcp, peer_addr)) => {
                    if request_logging {
                        eprintln!("Accepted TCP connection from {peer_addr}");
                    }
                    let acceptor = acceptor.clone();
                    let rpc = rpc.clone();
                    let auth = auth.clone();
                    let usage_log = usage_log.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp).await {
                            Ok(tls) => {
                                if request_logging {
                                    eprintln!("TLS handshake completed for {peer_addr}");
                                }
                                if let Err(e) = Http::new()
                                    .serve_connection(
                                        tls,
                                        service_fn(move |req| {
                                            handle_req_with_logging(
                                                req,
                                                rpc.clone(),
                                                auth.clone(),
                                                usage_log.clone(),
                                                RequestLogConfig::enabled_for_peer(peer_addr),
                                            )
                                        }),
                                    )
                                    .await
                                {
                                    eprintln!("Connection error: {}", e);
                                }
                            }
                            Err(e) => eprintln!("TLS handshake error: {}", e),
                        }
                    });
                }
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }
    } else {
        eprintln!("Listening on http://{}", addr);
        loop {
            match listener.accept().await {
                Ok((tcp, peer_addr)) => {
                    if request_logging {
                        eprintln!("Accepted TCP connection from {peer_addr}");
                    }
                    let rpc = rpc.clone();
                    let auth = auth.clone();
                    let usage_log = usage_log.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Http::new()
                            .serve_connection(
                                tcp,
                                service_fn(move |req| {
                                    handle_req_with_logging(
                                        req,
                                        rpc.clone(),
                                        auth.clone(),
                                        usage_log.clone(),
                                        RequestLogConfig::enabled_for_peer(peer_addr),
                                    )
                                }),
                            )
                            .await
                        {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }
    }
}
