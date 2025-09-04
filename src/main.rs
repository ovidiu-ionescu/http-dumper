use bytes::Bytes;
use clap::Parser;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::{Request, Response, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

static REQUES_ID_COUNTER: AtomicUsize = AtomicUsize::new(1);

#[derive(Parser, Debug)]
#[command(author, version, about, long_version = concat!(env!("CARGO_PKG_VERSION"), "\nauthor: ", env!("CARGO_PKG_AUTHORS"), "\n\n", env!("CARGO_PKG_DESCRIPTION")))]
struct Args {
  #[arg(short, long, default_value = "./cert.pem")]
  cert: String,
  #[arg(short, long, default_value = "./key.pem")]
  key: String,
  #[arg(short, long, default_value = "127.0.0.1:3000")]
  addr: String,
  #[arg(long, default_value = "false")]
  https: bool,
  #[arg(long, default_value = "false")]
  http2: bool,
}

async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
  let request_id = REQUES_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
  println!("{request_id} ----------------------");
  println!("Received request: {} {}", req.method(), req.uri());
  // print all the headers
  for (key, value) in req.headers() {
    println!("{key}: {value:?}");
  }
  let collected = req.collect().await?.to_bytes();
  match std::str::from_utf8(&collected) {
    Ok(s) => println!("Body: 「{s} 」"),
    Err(_) => eprintln!("Invalid UTF-8 received"),
  };
  Ok(Response::new(Full::new(Bytes::from("Hello, world!\n"))))
}

fn get_acceptor(http2: bool) -> TlsAcceptor {
  let certs = CertificateDer::pem_file_iter("./cert.pem")
    .unwrap()
    .map(|cert| cert.unwrap())
    .collect();
  let private_key = PrivateKeyDer::from_pem_file("./key.pem").unwrap();
  let mut config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(certs, private_key)
    .unwrap();
  config.alpn_protocols = if http2 {
    vec![b"h2".to_vec()]
  } else {
    vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()]
  };
  TlsAcceptor::from(Arc::new(config))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  let args = Args::parse();
  let addr: SocketAddr = args.addr.parse().expect("Invalid address format");

  // We create a TcpListener and bind it to 127.0.0.1:3000
  let listener = TcpListener::bind(addr).await?;
  println!("Listening to {addr}");
  // check if the arguments contain "https"
  if args.https {
    println!(
      "Starting HTTPS/{} server",
      if args.http2 { "2" } else { "1.1" }
    );
    do_https(listener, args.http2).await
  } else {
    println!(
      "Starting HTTP/{} server",
      if args.http2 { "2" } else { "1.1" }
    );
    do_http(listener, args.http2).await
  }
}

async fn do_https(
  tcp_listener: TcpListener, http2: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  let tls_acceptor = get_acceptor(http2);

  loop {
    let (stream, _) = tcp_listener.accept().await?;
    let tls_acceptor = tls_acceptor.clone();

    tokio::task::spawn(async move {
      let tls_stream = match tls_acceptor.accept(stream).await {
        Ok(tls_stream) => tls_stream,
        Err(e) => {
          eprintln!("TLS accept error: {e}");
          return;
        },
      };
      if let Err(err) = if http2 {
        http2::Builder::new(TokioExecutor::new())
          .serve_connection(TokioIo::new(tls_stream), service_fn(handle_request))
          .await
      } else {
        http1::Builder::new()
          .serve_connection(TokioIo::new(tls_stream), service_fn(handle_request))
          .await
      } {
        eprintln!("Error serving connection: {err:?}");
      }
    });
  }
}

async fn do_http(
  tcp_listener: TcpListener, http2: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
  loop {
    let (stream, _) = tcp_listener.accept().await?;
    tokio::task::spawn(async move {
      if let Err(err) = if http2 {
        http2::Builder::new(TokioExecutor::new())
          .serve_connection(TokioIo::new(stream), service_fn(handle_request))
          .await
      } else {
        http1::Builder::new()
          .serve_connection(TokioIo::new(stream), service_fn(handle_request))
          .await
      } {
        eprintln!("Error serving connection: {err:?}");
      }
    });
  }
}
