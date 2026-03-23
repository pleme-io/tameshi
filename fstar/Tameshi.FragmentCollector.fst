module Tameshi.FragmentCollector

open Tameshi.Hash

(** ================================================================
    Fragment Collection Threshold Security
    ================================================================
    Proves that K-of-N fragment collection correctly gates
    attestation authorization. *)

(** A collection result: how many fragments were gathered *)
type collection_result = {
  fragments_collected: nat;
  threshold: nat;
}

(** Is the collection authorized? *)
let is_authorized (r: collection_result) : Tot bool =
  r.fragments_collected >= r.threshold

(** Theorem: Below-threshold collection is never authorized. *)
let lemma_below_threshold_denies (r: collection_result)
  : Lemma
    (requires r.fragments_collected < r.threshold)
    (ensures is_authorized r = false)
  = ()

(** Theorem: At-or-above-threshold collection is always authorized. *)
let lemma_threshold_met_authorizes (r: collection_result)
  : Lemma
    (requires r.fragments_collected >= r.threshold)
    (ensures is_authorized r = true)
  = ()

(** Theorem: Anti-collusion — K-1 fragments are insufficient.
    Even if K-1 providers collude, they cannot reach threshold. *)
let lemma_anti_collusion (threshold: nat) (colluding: nat)
  : Lemma
    (requires colluding < threshold /\ threshold > 0)
    (ensures is_authorized { fragments_collected = colluding; threshold = threshold } = false)
  = ()

(** Theorem: Adding one honest provider to K-1 colluders reaches threshold. *)
let lemma_honest_provider_enables (threshold: nat) (colluding: nat)
  : Lemma
    (requires colluding = threshold - 1 /\ threshold > 0)
    (ensures is_authorized { fragments_collected = colluding + 1; threshold = threshold } = true)
  = ()
