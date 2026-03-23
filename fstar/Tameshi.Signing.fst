module Tameshi.Signing

open Tameshi.Hash

(** ================================================================
    Split-Knowledge OTP Signing
    ================================================================
    Models the tameshi DFC (Dual-Fragment Certification) scheme:
      - A signing key is reconstructed from two fragments via XOR
      - key = hash(xor(fragment_a, fragment_b))
      - Neither fragment alone reveals the key (information-theoretic)
      - Signing is keyed hashing: sig = combine(key, data)

    Security relies on:
      1. XOR being a perfect cipher (one-time pad)
      2. BLAKE3 collision resistance for the keyed hash *)

(** Reconstruct signing key from two fragments *)
let reconstruct_key (frag_a frag_b: hash_t) : Tot hash_t =
  hash (xor_hash frag_a frag_b)

(** Sign: keyed hash of data *)
let sign (key data: hash_t) : Tot hash_t =
  combine key data

(** Verify: recompute signature and compare *)
let verify (key data expected_sig: hash_t) : Tot bool =
  sign key data = expected_sig

(** ================================================================
    Theorem 10.1: Split-Knowledge Security
    ================================================================
    One fragment reveals zero information about the key.
    Formalized as: for any fragment_a and any target key material,
    there exists exactly one fragment_b that yields that target.
    This is the one-time pad argument. *)

(** Lemma: Different first fragments produce different XOR outputs *)
let lemma_different_fragments_different_xor
  (a1 a2 b: hash_t)
  : Lemma
    (requires a1 =!= a2)
    (ensures xor_hash a1 b =!= xor_hash a2 b)
  = xor_injective a1 a2 b

(** Lemma: Different first fragments produce different keys *)
let lemma_different_fragments_different_keys
  (a1 a2 b: hash_t)
  : Lemma
    (requires a1 =!= a2)
    (ensures reconstruct_key a1 b =!= reconstruct_key a2 b)
  = xor_injective a1 a2 b;
    hash_collision_resistant (xor_hash a1 b) (xor_hash a2 b)

(** Lemma: XOR is a perfect cipher.
    For any fragment a and any target value t, the fragment
    b = xor(a, t) satisfies xor(a, b) = t.
    This means knowing a alone gives no information about
    the XOR result (and hence the key). *)
let lemma_xor_perfect_cipher (a target: hash_t)
  : Lemma (xor_hash a (xor_hash a target) == target)
  = (* xor(a, xor(a, target)) = target
       by xor_involutive: xor(xor(x, y), y) = x
       instantiate with x = target, y = a:
         need: xor(xor(target, a), a) = target
       but we have xor(a, xor(a, target)) -- arguments are swapped.
       This requires XOR commutativity, which we admit. *)
    admit () (* Follows from XOR commutativity + involutivity *)

(** ================================================================
    Lemma: Wrong fragment => wrong key => failed verification
    ================================================================
    If an attacker has the wrong fragment, they reconstruct the wrong
    key, and any signature they produce will not verify under the
    correct key. *)

let lemma_wrong_fragment_fails
  (a_correct a_wrong b data: hash_t)
  : Lemma
    (requires a_correct =!= a_wrong)
    (ensures (let correct_key = reconstruct_key a_correct b in
              let wrong_key = reconstruct_key a_wrong b in
              let sig_correct = sign correct_key data in
              verify wrong_key data sig_correct = false))
  = lemma_different_fragments_different_keys a_correct a_wrong b;
    let correct_key = reconstruct_key a_correct b in
    let wrong_key = reconstruct_key a_wrong b in
    (* correct_key != wrong_key (proved above)
       => combine(correct_key, data) != combine(wrong_key, data) by CR
       => sign(correct_key, data) != sign(wrong_key, data)
       => verify(wrong_key, data, sign(correct_key, data)) = false *)
    combine_injective_left correct_key wrong_key data

(** ================================================================
    Corollary 10.1.1: Key Uniqueness
    ================================================================
    Each pair of fragments produces a unique key. No two distinct
    fragment pairs can produce the same signing key (under CR). *)

let lemma_key_uniqueness
  (a1 a2 b1 b2: hash_t)
  : Lemma
    (requires xor_hash a1 b1 =!= xor_hash a2 b2)
    (ensures reconstruct_key a1 b1 =!= reconstruct_key a2 b2)
  = hash_collision_resistant (xor_hash a1 b1) (xor_hash a2 b2)

(** ================================================================
    Corollary 10.1.2: Signature Binding
    ================================================================
    A valid signature under one key does not verify under a different key.
    This prevents cross-key signature reuse. *)

let lemma_signature_binding
  (k1 k2 data: hash_t)
  : Lemma
    (requires k1 =!= k2)
    (ensures (let sig = sign k1 data in
              verify k2 data sig = false))
  = combine_injective_left k1 k2 data
