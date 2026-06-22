@0xddc0ffee0b0e0001;

# DD-002 RPC-shape spike: project the navigation-heavy client port (scylla_port::Session)
# as a Cap'n Proto RPC interface, to validate that the port's shape survives the wire it was
# CHOSEN for (promise-pipelining). Throwaway — not the production surface.
#
# The key move: a lookup returns a CAPABILITY (Function), not data. capnp-rpc lets a client
# call methods on the not-yet-resolved capability — so `session.function(main).callers()` is
# ONE round-trip, the navigation pattern the port was designed around.

interface Session {
  # Look up a function by stable id -> a Function capability (the pipelining seam).
  function @0 (id :UInt64) -> (fn :Function);
  # Every function, as capabilities.
  functions @1 () -> (fns :List(Function));
}

interface Function {
  # The function's domain-zoom view (DD-020), as data.
  view @0 () -> (id :UInt64, name :Text, summary :Text, addr :UInt64, bbCount :UInt32);
  # The functions that call this one — again capabilities, so navigation chains pipeline.
  callers @1 () -> (fns :List(Function));
}
