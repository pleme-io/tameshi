module Tameshi.Chain

open FStar.Seq
open FStar.List.Tot
open Tameshi.Hash

(** ================================================================
    Hash Chain: append-only integrity log
    ================================================================
    Models the tameshi audit chain where each entry links to its
    predecessor via hash chaining. Provides:
      - Append-only integrity (Thm 7.1)
      - Tamper detection (Cor 7.1.1)
      - Fork detection (Cor 7.1.2) *)

(** A single chain entry *)
type chain_entry = {
  sequence: nat;
  entry_hash: hash_t;
  previous_hash: hash_t;
  payload: hash_t;
}

(** The zero hash used as genesis previous_hash *)
let zero_hash : hash_t = Seq.create 32 0uy

(** Compute entry hash: H(sequence || payload || previous_hash).
    We model the sequence number as its low byte for simplicity;
    the real implementation uses the full nat encoding. *)
let compute_entry_hash (seq_num: nat) (payload prev: hash_t) : Tot hash_t =
  let seq_byte = Seq.create 1 (UInt8.uint_to_t (seq_num % 256)) in
  combine (combine (hash seq_byte) payload) prev

(** Build a valid chain from a list of payloads *)
let rec build_chain (payloads: list hash_t) (seq_start: nat) (prev: hash_t)
  : Tot (list chain_entry)
        (decreases payloads)
  = match payloads with
    | [] -> []
    | p :: rest ->
      let eh = compute_entry_hash seq_start p prev in
      let entry = { sequence = seq_start;
                     entry_hash = eh;
                     previous_hash = prev;
                     payload = p } in
      entry :: build_chain rest (seq_start + 1) eh

(** Verify chain integrity: each entry's hash matches recomputation
    and links to the previous entry *)
let rec verify_chain (entries: list chain_entry) (expected_prev: hash_t)
  : Tot bool
        (decreases entries)
  = match entries with
    | [] -> true
    | e :: rest ->
      e.previous_hash = expected_prev &&
      e.entry_hash = compute_entry_hash e.sequence e.payload e.previous_hash &&
      verify_chain rest e.entry_hash

(** ================================================================
    Theorem 7.1: Chain Integrity
    ================================================================
    A correctly built chain always passes verification.
    Proved by induction on the payload list. *)

let rec lemma_chain_integrity
  (payloads: list hash_t) (seq_start: nat) (prev: hash_t)
  : Lemma (verify_chain (build_chain payloads seq_start prev) prev = true)
          (decreases payloads)
  = match payloads with
    | [] -> ()
    | p :: rest ->
      let eh = compute_entry_hash seq_start p prev in
      (* After building the first entry, the chain from rest starts at eh *)
      lemma_chain_integrity rest (seq_start + 1) eh

(** ================================================================
    Corollary 7.1.1: Tamper Detection
    ================================================================
    If a chain verifies successfully, each entry's hash is consistent
    with its payload and predecessor. Modifying any entry's payload
    without updating its hash will cause verification to fail.

    This is a definitional consequence: verify_chain checks the hash
    recomputation at every step. *)

let lemma_tamper_detection
  (entries: list chain_entry) (prev: hash_t)
  : Lemma
    (requires verify_chain entries prev = true)
    (ensures (match entries with
              | [] -> True
              | e :: _ ->
                e.previous_hash = prev /\
                e.entry_hash = compute_entry_hash e.sequence e.payload e.previous_hash))
  = ()

(** Stronger tamper detection: modifying a payload changes the entry hash *)
let lemma_payload_tamper
  (seq_num: nat) (payload1 payload2 prev: hash_t)
  : Lemma
    (requires payload1 =!= payload2)
    (ensures compute_entry_hash seq_num payload1 prev =!=
             compute_entry_hash seq_num payload2 prev)
  = (* H(H(seq) || p1) != H(H(seq) || p2) when p1 != p2
       This follows from combine being injective in its second argument
       applied to the inner combine, then CR on the outer combine. *)
    let seq_byte = Seq.create 1 (UInt8.uint_to_t (seq_num % 256)) in
    let seq_hash = hash seq_byte in
    combine_injective_right seq_hash payload1 payload2;
    let inner1 = combine seq_hash payload1 in
    let inner2 = combine seq_hash payload2 in
    combine_injective_left inner1 inner2 prev

(** ================================================================
    Corollary 7.1.2: Fork Detection
    ================================================================
    Two chains sharing a common prefix but diverging at position k
    will have different entry hashes from position k onward.
    An auditor comparing chain heads detects the fork. *)

let lemma_fork_detection
  (payload_a payload_b: hash_t)
  (seq_num: nat) (prev: hash_t)
  : Lemma
    (requires payload_a =!= payload_b)
    (ensures compute_entry_hash seq_num payload_a prev =!=
             compute_entry_hash seq_num payload_b prev)
  = lemma_payload_tamper seq_num payload_a payload_b prev

(** Chain length is preserved *)
let rec lemma_build_chain_length
  (payloads: list hash_t) (seq_start: nat) (prev: hash_t)
  : Lemma (List.Tot.length (build_chain payloads seq_start prev) =
           List.Tot.length payloads)
          (decreases payloads)
  = match payloads with
    | [] -> ()
    | _ :: rest ->
      let eh = compute_entry_hash seq_start (List.Tot.hd payloads) prev in
      lemma_build_chain_length rest (seq_start + 1) eh
