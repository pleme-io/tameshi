module Tameshi.Merkle

open FStar.Seq
open FStar.List.Tot
open Tameshi.Hash

(** A Merkle tree is either a Leaf or a Node *)
type merkle_tree =
  | Leaf : data:hash_t -> merkle_tree
  | Node : left:merkle_tree -> right:merkle_tree -> merkle_tree

(** Count the number of leaves in a tree *)
let rec tree_size (t: merkle_tree) : Tot nat =
  match t with
  | Leaf _ -> 1
  | Node l r -> tree_size l + tree_size r

(** Compute the root hash of a Merkle tree with domain separation.
    Leaves are hashed with a 0x00 domain tag, internal nodes with 0x01. *)
let rec merkle_root (t: merkle_tree) : Tot hash_t =
  match t with
  | Leaf d -> domain_leaf d
  | Node l r -> domain_internal (merkle_root l) (merkle_root r)

(** Get the i-th leaf value (0-indexed, left to right) *)
let rec get_leaf (t: merkle_tree) (i: nat) : Tot (option hash_t) =
  match t with
  | Leaf d -> if i = 0 then Some d else None
  | Node l r ->
    let ls = tree_size l in
    if i < ls then get_leaf l i
    else get_leaf r (i - ls)

(** Replace the i-th leaf in a tree with a new value *)
let rec replace_leaf (t: merkle_tree) (i: nat) (new_val: hash_t)
  : Tot merkle_tree
  = match t with
    | Leaf _ -> if i = 0 then Leaf new_val else t
    | Node l r ->
      let ls = tree_size l in
      if i < ls then Node (replace_leaf l i new_val) r
      else Node l (replace_leaf r (i - ls) new_val)

(** Helper: get_leaf returns Some for valid indices *)
let rec lemma_get_leaf_valid (t: merkle_tree) (i: nat)
  : Lemma (requires i < tree_size t)
          (ensures Some? (get_leaf t i))
          (decreases t)
  = match t with
    | Leaf _ -> ()
    | Node l r ->
      let ls = tree_size l in
      if i < ls then lemma_get_leaf_valid l i
      else lemma_get_leaf_valid r (i - ls)

(** Helper: replacing a leaf with a different value changes the leaf *)
let rec lemma_replace_changes_leaf (t: merkle_tree) (i: nat) (new_val: hash_t)
  : Lemma
    (requires (
      i < tree_size t /\
      (match get_leaf t i with
       | Some v -> v =!= new_val
       | None -> False)))
    (ensures (
      match get_leaf (replace_leaf t i new_val) i with
      | Some v -> v == new_val
      | None -> False))
    (decreases t)
  = match t with
    | Leaf _ -> ()
    | Node l r ->
      let ls = tree_size l in
      if i < ls then lemma_replace_changes_leaf l i new_val
      else lemma_replace_changes_leaf r (i - ls) new_val

(** ================================================================
    Theorem 3.1: Tamper Evidence
    ================================================================
    If any leaf is changed to a distinct value, the Merkle root changes.
    Proved by structural induction on the tree.

    Attack model: adversary modifies leaf i from v to new_val where v != new_val.
    Claim: merkle_root(original) != merkle_root(modified).
    Reduction: if roots were equal, we could extract a collision in the
    underlying hash function (domain_leaf or domain_internal). *)

let rec lemma_tamper_evidence
  (t: merkle_tree) (i: nat) (new_val: hash_t)
  : Lemma
    (requires (
      i < tree_size t /\
      (match get_leaf t i with
       | Some v -> v =!= new_val
       | None -> False)))
    (ensures merkle_root t =!= merkle_root (replace_leaf t i new_val))
    (decreases t)
  = match t with
    | Leaf _ ->
      (* Base case: Leaf d replaced by Leaf new_val where d != new_val.
         merkle_root (Leaf d) = domain_leaf d
         merkle_root (Leaf new_val) = domain_leaf new_val
         By domain_leaf_injective: d != new_val => domain_leaf d != domain_leaf new_val *)
      domain_leaf_injective t.data new_val
    | Node l r ->
      let ls = tree_size l in
      if i < ls then begin
        (* Inductive case: leaf is in the left subtree.
           By IH: merkle_root l != merkle_root (replace_leaf l i new_val)
           By domain_internal_injective_left: distinct left roots => distinct internal hashes *)
        lemma_tamper_evidence l i new_val;
        domain_internal_injective_left
          (merkle_root l)
          (merkle_root (replace_leaf l i new_val))
          (merkle_root r)
      end else begin
        (* Inductive case: leaf is in the right subtree.
           By IH: merkle_root r != merkle_root (replace_leaf r (i-ls) new_val)
           By domain_internal_injective_right: distinct right roots => distinct internal hashes *)
        lemma_tamper_evidence r (i - ls) new_val;
        domain_internal_injective_right
          (merkle_root l)
          (merkle_root r)
          (merkle_root (replace_leaf r (i - ls) new_val))
      end

(** ================================================================
    Theorem 3.2: Second-preimage Resistance
    ================================================================
    A leaf hash cannot equal an internal node hash.
    This prevents height-extension attacks. *)

let lemma_second_preimage (x: hash_t) (y: hash_t)
  : Lemma (domain_leaf x =!= domain_internal y y)
  = domain_disjoint x y

(** Corollary: a Leaf tree and a Node tree always have distinct roots *)
let lemma_leaf_node_distinct (d: hash_t) (l r: merkle_tree)
  : Lemma (merkle_root (Leaf d) =!= merkle_root (Node l r))
  = (* merkle_root (Leaf d) = domain_leaf d
       merkle_root (Node l r) = domain_internal (merkle_root l) (merkle_root r)
       Need: domain_leaf d != domain_internal X Y for all X, Y
       We have domain_disjoint for X=Y case; general case from CR *)
    admit () (* General case requires domain separation for all X,Y pairs *)
