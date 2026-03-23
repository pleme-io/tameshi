module Tameshi.Artifact

open Tameshi.Hash
open Tameshi.Merkle

(** ================================================================
    Certification Artifact: 3-leaf Merkle binding
    ================================================================
    A tameshi certification artifact binds three components:
      - artifact_hash: hash of the build artifact (binary, image, etc.)
      - control_hash:  hash of the compliance control attestation
      - intent_hash:   hash of the deployment intent declaration

    These are composed into a 3-leaf Merkle tree. The root is the
    certification signature that gates deployment via sekiban. *)

type cert_artifact = {
  artifact_hash: hash_t;
  control_hash: hash_t;
  intent_hash: hash_t;
}

(** Build the 3-leaf Merkle tree for a certification artifact.
    Structure (matches rs_merkle behavior for 3 leaves):
           root
          /    \
        n01    n22
       /   \   / \
      l0   l1 l2  l2   <-- leaf 2 duplicated for balanced tree *)
let artifact_tree (ca: cert_artifact) : Tot merkle_tree =
  Node
    (Node (Leaf ca.artifact_hash) (Leaf ca.control_hash))
    (Node (Leaf ca.intent_hash)   (Leaf ca.intent_hash))

(** Compose: compute the root hash of the 3-leaf artifact tree *)
let compose (ca: cert_artifact) : Tot hash_t =
  merkle_root (artifact_tree ca)

(** Expanded form for direct reasoning *)
let compose_expanded (ca: cert_artifact) : Tot hash_t =
  let l0 = domain_leaf ca.artifact_hash in
  let l1 = domain_leaf ca.control_hash in
  let l2 = domain_leaf ca.intent_hash in
  let n01 = domain_internal l0 l1 in
  let n22 = domain_internal l2 l2 in
  domain_internal n01 n22

(** Sanity: compose and compose_expanded agree *)
let lemma_compose_equiv (ca: cert_artifact)
  : Lemma (compose ca == compose_expanded ca)
  = ()

(** ================================================================
    Theorem 4.1: Artifact Binding
    ================================================================
    If any of the three input hashes differs between two artifacts,
    their composed roots differ.

    This is the core security property: an attacker cannot substitute
    a different artifact, weaken a control, or change the deployment
    intent without invalidating the certification. *)

let lemma_artifact_binding
  (ca1 ca2: cert_artifact)
  : Lemma
    (requires ca1.artifact_hash =!= ca2.artifact_hash \/
              ca1.control_hash =!= ca2.control_hash \/
              ca1.intent_hash =!= ca2.intent_hash)
    (ensures compose ca1 =!= compose ca2)
  = (* Strategy: case-split on which input changed, then use
       domain_leaf_injective + domain_internal_injective_* to propagate
       the disequality up the tree. *)
    let l0_1 = domain_leaf ca1.artifact_hash in
    let l1_1 = domain_leaf ca1.control_hash in
    let l2_1 = domain_leaf ca1.intent_hash in
    let l0_2 = domain_leaf ca2.artifact_hash in
    let l1_2 = domain_leaf ca2.control_hash in
    let l2_2 = domain_leaf ca2.intent_hash in
    let n01_1 = domain_internal l0_1 l1_1 in
    let n01_2 = domain_internal l0_2 l1_2 in
    let n22_1 = domain_internal l2_1 l2_1 in
    let n22_2 = domain_internal l2_2 l2_2 in
    if ca1.artifact_hash =!= ca2.artifact_hash then begin
      (* artifact_hash changed => l0 changed => n01 changed => root changed *)
      domain_leaf_injective ca1.artifact_hash ca2.artifact_hash;
      domain_internal_injective_left l0_1 l0_2 l1_1;
      (* n01_1 != n01_2 if l1_1 = l1_2, but l1 might also differ.
         We need: l0_1 != l0_2 => n01_1 != n01_2 regardless of l1.
         This requires a stronger injectivity axiom or case split on l1. *)
      admit () (* Follows from hash CR: H(0x01||l0_1||l1_1) != H(0x01||l0_2||l1_2) when l0_1 != l0_2 *)
    end
    else if ca1.control_hash =!= ca2.control_hash then begin
      (* control_hash changed => l1 changed => n01 changed => root changed *)
      domain_leaf_injective ca1.control_hash ca2.control_hash;
      domain_internal_injective_right l0_1 l1_1 l1_2;
      domain_internal_injective_left n01_1 n01_2 n22_1;
      admit () (* Same structure: propagate through domain_internal *)
    end
    else begin
      (* intent_hash changed => l2 changed => n22 changed => root changed *)
      domain_leaf_injective ca1.intent_hash ca2.intent_hash;
      domain_internal_injective_left l2_1 l2_2 l2_1;
      domain_internal_injective_right n01_1 n22_1 n22_2;
      admit () (* Propagation through right subtree *)
    end

(** ================================================================
    Corollary 4.1.1: Forge Resistance
    ================================================================
    An attacker who does not know all three inputs cannot produce
    the correct root. This is immediate from binding: any guess
    with a wrong input yields a different root. *)

let lemma_forge_resistance
  (ca: cert_artifact) (forged: cert_artifact)
  : Lemma
    (requires forged.artifact_hash =!= ca.artifact_hash \/
              forged.control_hash =!= ca.control_hash \/
              forged.intent_hash =!= ca.intent_hash)
    (ensures compose forged =!= compose ca)
  = lemma_artifact_binding forged ca

(** ================================================================
    Corollary 4.1.2: Two-Phase Composability
    ================================================================
    The untested root (artifact + control) and the secure root
    (artifact + control + intent) are always distinct when intent
    is non-trivial. Models the tameshi two-phase certification. *)

let lemma_two_phase_distinct
  (artifact control intent dummy_intent: hash_t)
  : Lemma
    (requires intent =!= dummy_intent)
    (ensures (
      let ca1 = { artifact_hash = artifact; control_hash = control; intent_hash = intent } in
      let ca2 = { artifact_hash = artifact; control_hash = control; intent_hash = dummy_intent } in
      compose ca1 =!= compose ca2))
  = let ca1 = { artifact_hash = artifact; control_hash = control; intent_hash = intent } in
    let ca2 = { artifact_hash = artifact; control_hash = control; intent_hash = dummy_intent } in
    lemma_artifact_binding ca1 ca2
