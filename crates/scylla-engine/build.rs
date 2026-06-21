fn main() {
    tonic_build::compile_protos("proto/engine.proto").expect("compiling proto/engine.proto");
}
