@0xddc0ffee0b0e0002;

# DD-002 — the client port (`scylla_port::Session`) projected as a Cap'n Proto RPC `interface`,
# the promise-pipelining transport the model-artifact format was chosen for. This is the REMOTE
# projection of the same port the in-process heads (mcp/wasm/serve/cli) drive — a head not
# co-located with the core finally needs it (the DD-002 deferral's precondition).
#
# The key move (validated by spike/rpc-shape): a lookup returns a CAPABILITY (Function), not data.
# capnp-rpc lets a client call methods on the not-yet-resolved capability, so the navigation chain
# `session.function(id).callers().view()` is ONE round-trip — the pattern the port was designed for.
#
# Zoom is the DD-020 altitude as a u8 (0 = intent, 1 = domain, 2 = detail). Mutating verbs map a
# rejected value (PortError::InvalidInput, DD-021) straight to a capnp::Error.

# The bootstrap capability: you don't get a `Session` (any authority at all) until you authenticate
# (DD-035). Capability-based auth — a wrong token yields a capnp::Error, not a Session. When the
# server is started without a configured token it runs OPEN (login accepts anything, with a warning).
interface Authenticator {
  login @0 (token :Text) -> (session :Session);
}

# A function pairing across two builds, by display name (DD-017 diff).
struct FnPair {
  here  @0 :Text;
  there @1 :Text;
}

interface Session {
  # Artifact metadata (name / language / function count).
  info @0 () -> (name :Text, language :Text, functions :UInt32);
  # Every function, as capabilities. (A capability is zoom-agnostic — pick the altitude at `view`.)
  functions @1 () -> (fns :List(Function));
  # Look up one function by stable id -> a Function capability (the pipelining seam).
  function @2 (id :UInt64) -> (fn :Function);
  # Structurally diff the served model against another .scylla (sent as bytes) — DD-017, read-only.
  # `matched` is the unchanged count; renamed/modified are name pairs; added/removed are names.
  diff @3 (artifact :Data) -> (matched :UInt32, renamed :List(FnPair), modified :List(FnPair), added :List(Text), removed :List(Text));
}

interface Function {
  # The function's view at a zoom altitude (DD-020). Fields above the altitude come back zeroed.
  view @0 (zoom :UInt8) -> (id :UInt64, name :Text, summary :Text, addr :UInt64, bbCount :UInt32, size :UInt64);
  # The functions that call this one — capabilities again, so navigation chains pipeline.
  callers @1 () -> (fns :List(Function));
  # Durable user facts (DD-005). A rejected value (e.g. a blank name) -> a capnp::Error (DD-021).
  rename @2 (name :Text) -> ();
  retype @3 (type :Text) -> ();
  comment @4 (text :Text) -> ();
}
