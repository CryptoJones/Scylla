//! Cross-language smoke: the Rust engine-port client (tonic) calling the JVM engine-service
//! (grpc-java). Start the service, then: `cargo run -p scylla-engine --example probe`.
use scylla_engine::pb::engine_client::EngineClient;
use scylla_engine::pb::{materialize_event::Event, InfoRequest, MaterializeRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:50051".into());
    let mut client = EngineClient::connect(addr).await?;

    let info = client.info(InfoRequest {}).await?.into_inner();
    println!("Info: engine={} version={}", info.engine, info.version);

    // Send a real binary's bytes if a path is given (arg 2); else an empty request.
    let binary = std::env::args().nth(2).map(|p| std::fs::read(p).unwrap_or_default()).unwrap_or_default();
    let mut stream = client
        .materialize(MaterializeRequest { binary, arch_hint: String::new() })
        .await?
        .into_inner();
    let mut n = 0;
    while let Some(ev) = stream.message().await? {
        match ev.event {
            Some(Event::Info(info)) => {
                println!("Program: name={} language={}", info.name, info.language)
            }
            Some(Event::Function(chunk)) => {
                println!("  fn {:#x} {} (bb={})", chunk.entry, chunk.name, chunk.bb_count);
                n += 1;
            }
            None => {}
        }
    }
    println!("Materialize streamed {n} functions");
    Ok(())
}
