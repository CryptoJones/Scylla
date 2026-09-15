fn main() {
    if let Err(e) = tonic_build::compile_protos("proto/engine.proto") {
        panic!(
            "\n\n================================================================================\n\
             BUILD ERROR: Failed to compile Protocol Buffers: {e}\n\n\
             Native prerequisite 'protoc' is required to build scylla-engine.\n\
             Install instructions:\n\
               - macOS:   brew install protobuf\n\
               - Ubuntu:  sudo apt-get install protobuf-compiler\n\
               - Arch:    sudo pacman -S protobuf\n\
               - Windows: choco install protoc / scoop install protobuf\n\
             ================================================================================\n\n"
        );
    }
}
