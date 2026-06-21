@0xbb2bf60424e0ddd9;
# Scylla canonical model artifact (DD-002: Cap'n Proto, DD-026: our own format).
# Zero-copy on disk / wire; the in-core working model is the native Rust graph that
# serializes *to* this (DD-002 resolution).

struct Program {
  name      @0 :Text;
  language  @1 :Text;
  functions @2 :List(Function);
  facts     @3 :List(UserFact);
}

struct Function {
  id          @0 :UInt64;   # synthetic stable id (DD-004) — NOT the address
  addr        @1 :UInt64;   # mutable attribute
  name        @2 :Text;     # engine symbol; user renames live in UserFact
  size        @3 :UInt64;
  bbCount     @4 :UInt32;
  callees     @5 :List(UInt64);
  fingerprint @6 :UInt64;   # structural hash of the mnemonic histogram; 0 = engine emitted none.
                            # Disambiguates coarse-signature collisions in EXACT re-anchoring (DD-038).
  mnemonics   @7 :List(MnemonicCount);  # the instruction histogram itself — the FUZZY re-anchoring
                                        # matcher scores cosine over these (DD-038 follow-up).
}

struct MnemonicCount {
  mnemonic @0 :Text;
  count    @1 :UInt32;
}

struct UserFact {
  target @0 :UInt64;   # edge onto a stable id (DD-005)
  kind   @1 :UInt16;   # 0=rename 1=retype 2=comment  (union refinement: TODO)
  value  @2 :Text;
  author @3 :Text;     # who made it (DD-035 identity seam; empty string = none)
}
