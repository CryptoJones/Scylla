fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/scylla_rpc.capnp")
        .run()
        .expect("compiling schema/scylla_rpc.capnp");
}
