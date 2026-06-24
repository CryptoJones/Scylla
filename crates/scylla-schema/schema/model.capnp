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
  stringRefs  @8 :List(Text);   # referenced string literals — ARCH-INDEPENDENT (DD-041): survive a
                                # recompile for a different ISA, where mnemonics/addresses don't.
  imports     @9 :List(Text);   # imported/library calls BY NAME (printf, atoi, …) — arch-independent
                                # too. stringRefs+imports drive the cross-architecture ANCHOR pass.
  calleeNames @10 :List(Text);  # PACKAGE-QUALIFIED callee names (fmt.Fprintf, main.fib) — the Go
                                # cross-arch lever (DD-043): survive .gopclntab stripping, ISA-stable.
  bsimVector  @11 :List(BsimFeature);  # BSim decompiler-signature LSH feature vector (DD-044): the
                                # ISA-abstracting cross-architecture lever for the symmetric arithmetic
                                # leaves (factorial/sum_to) that strings/imports/callee-names/mnemonics
                                # all miss. A weighted cosine over these == Ghidra's LSHVector.compare,
                                # because the producer bakes BSim's feature weights into the coeffs.
  trigrams    @12 :List(MnemonicCount);  # ORDERED mnemonic trigrams (length-3 instruction windows)
                                # as a histogram — the local-order signal the order-independent
                                # `mnemonics` histogram discards. Folded into the FUZZY cosine. Empty
                                # for functions with < 3 instructions or no mnemonic data.
}

struct BsimFeature {
  hash   @0 :UInt32;   # decompiler p-code feature hash
  weight @1 :UInt32;   # IEEE-754 bits of the f32 coefficient (kept integral so the model is exact)
}

struct MnemonicCount {
  mnemonic @0 :Text;
  count    @1 :UInt32;
}

struct UserFact {
  target     @0 :UInt64;   # edge onto a stable id (DD-005)
  kind       @1 :UInt16;   # 0=rename 1=retype 2=comment  (union refinement: TODO)
  value      @2 :Text;
  author     @3 :Text;     # who made it (DD-035 identity seam; empty string = none)
  producer   @4 :Text;     # provenance (DD-007): producer label; empty = legacy artifact => "user"
  confidence @5 :UInt8;    # provenance (DD-007): 0..=100 trust; read only when producer is set
}
