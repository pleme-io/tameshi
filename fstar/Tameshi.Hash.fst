module Tameshi.Hash

open FStar.Seq

(** All axioms are admitted -- they model cryptographic assumptions.
    The implementations return dummy values; only the interface (fsti)
    matters for downstream proofs. *)

let hash (_x: seq UInt8.t) : Tot hash_t = admit (); Seq.create 32 0uy
let combine (_a _b: hash_t) : Tot hash_t = admit (); Seq.create 32 0uy
let domain_leaf (_x: hash_t) : Tot hash_t = admit (); Seq.create 32 0uy
let domain_internal (_l _r: hash_t) : Tot hash_t = admit (); Seq.create 32 0uy
let xor_hash (_a _b: hash_t) : Tot hash_t = admit (); Seq.create 32 0uy

let hash_deterministic (_x: seq UInt8.t) = ()
let hash_collision_resistant (_x _y: seq UInt8.t) = admit ()
let combine_injective_left (_a1 _a2 _b: hash_t) = admit ()
let combine_injective_right (_a _b1 _b2: hash_t) = admit ()
let combine_non_commutative (_a _b: hash_t) = admit ()
let domain_leaf_injective (_x _y: hash_t) = admit ()
let domain_internal_injective_left (_l1 _l2 _r: hash_t) = admit ()
let domain_internal_injective_right (_l _r1 _r2: hash_t) = admit ()
let domain_disjoint (_x _y: hash_t) = admit ()
let domain_disjoint_general (_x _y1 _y2: hash_t) = admit ()
let xor_involutive (_a _b: hash_t) = admit ()
let xor_injective (_a1 _a2 _b: hash_t) = admit ()
