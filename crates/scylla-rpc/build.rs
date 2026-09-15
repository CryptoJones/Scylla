fn main() {
    if let Err(e) = capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/scylla_rpc.capnp")
        .run()
    {
        panic!(
            "\n\n================================================================================\n\
             BUILD ERROR: Failed to compile Cap'n Proto schema: {e}\n\n\
             Native prerequisite 'capnp' is required to build Scylla.\n\
             Install instructions:\n\
               - macOS:   brew install capnp\n\
               - Ubuntu:  sudo apt-get install capnproto\n\
               - Arch:    sudo pacman -S capnproto\n\
               - Windows: choco install capnproto / scoop install capnproto\n\
             ================================================================================\n\n"
        );
    }
}
