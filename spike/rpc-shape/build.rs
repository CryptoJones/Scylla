fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/port.capnp")
        .run()
        .expect("compiling schema/port.capnp");
}
