fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/model.capnp")
        .run()
        .expect("compiling schema/model.capnp");
}
