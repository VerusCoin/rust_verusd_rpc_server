use rust_verusd_rpc_server::{VerusRPC, handle_req, load_tls_config};
use hyper::{server::conn::Http, service::service_fn};
use std::sync::Arc;
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

    let url      = settings.get_string("rpc_url").expect("Failed to read 'rpc_url' from configuration");
    let user     = secrets.get_string("rpc_user").expect("Failed to read 'rpc_user' from configuration");
    let password = secrets.get_string("rpc_password").expect("Failed to read 'rpc_password' from configuration");

    let port        = settings.get::<u16>("server_port").expect("Failed to read 'server_port' from configuration");
    let server_addr = settings.get_string("server_addr").expect("Failed to read 'server_addr' from configuration");

    let rpc = Arc::new(VerusRPC::new(&url, &user, &password).unwrap());

    let addr: std::net::SocketAddr = (
        server_addr.parse::<std::net::IpAddr>().expect("Invalid server_addr in configuration"),
        port,
    ).into();

    let listener = TcpListener::bind(addr).await.expect("Failed to bind server address");

    let tls_enabled = settings.get::<bool>("tls_enabled").unwrap_or(false);

    if tls_enabled {
        let cert_path = secrets.get_string("tls_cert_path")
            .expect("'tls_cert_path' is required when tls_enabled = true");
        let key_path = secrets.get_string("tls_key_path")
            .expect("'tls_key_path' is required when tls_enabled = true");

        let tls_config = load_tls_config(&cert_path, &key_path)
            .expect("Failed to load TLS certificate/key");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        eprintln!("Listening on https://{}", addr);
        loop {
            match listener.accept().await {
                Ok((tcp, _)) => {
                    let acceptor = acceptor.clone();
                    let rpc = rpc.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(tcp).await {
                            Ok(tls) => {
                                if let Err(e) = Http::new()
                                    .serve_connection(tls, service_fn(move |req| handle_req(req, rpc.clone())))
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
                Ok((tcp, _)) => {
                    let rpc = rpc.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Http::new()
                            .serve_connection(tcp, service_fn(move |req| handle_req(req, rpc.clone())))
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
