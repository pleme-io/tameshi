module Tameshi.Hash

open FStar.Seq

(** Abstract hash type -- 32-byte sequence *)
type hash_t = s:seq UInt8.t{Seq.length s = 32}

(** Abstract hash function -- models BLAKE3 *)
val hash: seq UInt8.t -> Tot hash_t

(** Combine two hashes -- models Blake3Hash::combine *)
val combine: hash_t -> hash_t -> Tot hash_t

(** Domain-separated leaf hash: hash(0x00 || data) *)
val domain_leaf: hash_t -> Tot hash_t

(** Domain-separated internal node hash: hash(0x01 || left || right) *)
val domain_internal: hash_t -> hash_t -> Tot hash_t

(** XOR of two hashes -- models split-knowledge fragment XOR *)
val xor_hash: hash_t -> hash_t -> Tot hash_t

(** Axiom: Determinism -- same input, same output *)
val hash_deterministic: x:seq UInt8.t -> Lemma (hash x == hash x)

(** Axiom: Collision resistance -- distinct inputs, distinct outputs.
    This is an idealization; real CR only holds with overwhelming probability.
    We use admit() in the implementation to mark this as an assumption. *)
val hash_collision_resistant:
  x:seq UInt8.t -> y:seq UInt8.t ->
  Lemma (requires x =!= y)
        (ensures hash x =!= hash y)

(** Axiom: Combine is injective -- distinct first arguments yield distinct outputs *)
val combine_injective_left:
  a1:hash_t -> a2:hash_t -> b:hash_t ->
  Lemma (requires a1 =!= a2)
        (ensures combine a1 b =!= combine a2 b)

(** Axiom: Combine is injective in second argument *)
val combine_injective_right:
  a:hash_t -> b1:hash_t -> b2:hash_t ->
  Lemma (requires b1 =!= b2)
        (ensures combine a b1 =!= combine a b2)

(** Axiom: Combine is non-commutative for distinct inputs *)
val combine_non_commutative:
  a:hash_t -> b:hash_t ->
  Lemma (requires a =!= b)
        (ensures combine a b =!= combine b a)

(** Axiom: Domain-separated leaf hash is injective *)
val domain_leaf_injective:
  x:hash_t -> y:hash_t ->
  Lemma (requires x =!= y)
        (ensures domain_leaf x =!= domain_leaf y)

(** Axiom: Domain-separated internal hash is injective in first argument *)
val domain_internal_injective_left:
  l1:hash_t -> l2:hash_t -> r:hash_t ->
  Lemma (requires l1 =!= l2)
        (ensures domain_internal l1 r =!= domain_internal l2 r)

(** Axiom: Domain-separated internal hash is injective in second argument *)
val domain_internal_injective_right:
  l:hash_t -> r1:hash_t -> r2:hash_t ->
  Lemma (requires r1 =!= r2)
        (ensures domain_internal l r1 =!= domain_internal l r2)

(** Axiom: Domain separation -- leaf and internal domains are disjoint *)
val domain_disjoint:
  x:hash_t -> y:hash_t ->
  Lemma (domain_leaf x =!= domain_internal y y)

(** Axiom: XOR is its own inverse *)
val xor_involutive:
  a:hash_t -> b:hash_t ->
  Lemma (xor_hash (xor_hash a b) b == a)

(** Axiom: XOR is injective in first argument *)
val xor_injective:
  a1:hash_t -> a2:hash_t -> b:hash_t ->
  Lemma (requires a1 =!= a2)
        (ensures xor_hash a1 b =!= xor_hash a2 b)
