//! Cross-language smoke: the Rust engine-port client (tonic) calling the JVM engine-service
//! (grpc-java). Start the service, then: `cargo run -p scylla-engine --example probe`.
use scylla_engine::pb::engine_client::EngineClient;
use scylla_engine::pb::{InfoRequest, MaterializeRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let mut client = EngineClient::connect(addr).await?;

    let info = client.info(InfoRequest {}).await?.into_inner();
    println!("Info: engine={} version={}", info.engine, info.version);

    let mut stream = client
        .materialize(MaterializeRequest { binary: vec![], arch_hint: String::new() })
        .await?
        .into_inner();
    let mut n = 0;
    while let Some(chunk) = stream.message().await? {
        println!("  fn {:#x} {} (bb={})", chunk.entry, chunk.name, chunk.bb_count);
        n += 1;
    }
    println!("Materialize streamed {n} functions");
    Ok(())
}
