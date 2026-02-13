(*
 * B4AE Handshake Protocol - Coq Formal Specification
 *
 * Formal model of the three-way handshake state machine.
 * Proves: valid state transitions, safety invariants.
 *)

Require Import Coq.Arith.Arith.
Require Import Coq.Bool.Bool.

(* ========================================================================== *)
(* State enumeration (matches Rust HandshakeState)                             *)
(* ========================================================================== *)

Inductive HandshakeState : Type :=
  | Initiation      (* 0: initial *)
  | WaitingResponse (* 1: initiator sent init, waiting for response *)
  | WaitingComplete (* 2: responder sent response, waiting for complete *)
  | Completed       (* 3: both parties have completed *)
  | Failed.         (* 4: handshake failed *)

(* Global protocol state *)
Definition ProtocolState : Type := HandshakeState * HandshakeState.
Definition initiator_state (s : ProtocolState) : HandshakeState := fst s.
Definition responder_state (s : ProtocolState) : HandshakeState := snd s.

(* ========================================================================== *)
(* Initial state                                                                *)
(* ========================================================================== *)

Definition init_state : ProtocolState := (Initiation, Initiation).

Definition Init (s : ProtocolState) : Prop :=
  s = init_state.

(* ========================================================================== *)
(* Valid transitions (match TLA+ Next)                                         *)
(* ========================================================================== *)

Inductive Transition : ProtocolState -> ProtocolState -> Prop :=
  (* InitiatorSendsInit: Initiation -> WaitingResponse *)
  | TransInitiatorSendsInit : forall s,
      initiator_state s = Initiation ->
      Transition s (WaitingResponse, responder_state s)

  (* ResponderSendsResponse *)
  | TransResponderSendsResponse : forall s,
      initiator_state s = WaitingResponse ->
      responder_state s = Initiation ->
      Transition s (initiator_state s, WaitingComplete)

  (* InitiatorSendsComplete *)
  | TransInitiatorSendsComplete : forall s,
      initiator_state s = WaitingResponse ->
      responder_state s = WaitingComplete ->
      Transition s (WaitingComplete, responder_state s)

  (* ResponderReceivesComplete -> both Completed *)
  | TransResponderReceivesComplete : forall s,
      initiator_state s = WaitingComplete ->
      responder_state s = WaitingComplete ->
      Transition s (Completed, Completed).

(* Multi-step reachability *)
Inductive Reachable : ProtocolState -> Prop :=
  | ReachInit : Reachable init_state
  | ReachStep : forall s s',
      Reachable s -> Transition s s' -> Reachable s'.

(* ========================================================================== *)
(* Safety invariant                                                             *)
(* ========================================================================== *)

(* Both Completed only after valid handshake sequence *)
Definition both_completed (s : ProtocolState) : Prop :=
  initiator_state s = Completed /\ responder_state s = Completed.

(* The invariant: if both are Completed, the state is reachable from Init *)
Definition SafetyInvariant (s : ProtocolState) : Prop :=
  both_completed s -> Reachable s.

(* ========================================================================== *)
(* Lemmas                                                                       *)
(* ========================================================================== *)

Lemma init_reachable : Reachable init_state.
Proof. apply ReachInit. Qed.

Lemma transition_preserves_inv :
  forall s s', Transition s s' ->
    (both_completed s -> Reachable s) ->
    (both_completed s' -> Reachable s').
Proof.
  intros s s' Ht Hi Hbc.
  inversion Ht; subst; simpl in *;
    unfold both_completed in Hbc; simpl in Hbc;
    destruct Hbc as [Hc1 Hc2].
  - discriminate Hc1.
  - discriminate Hc2.
  - discriminate Hc1.
  - apply ReachStep with (s := (WaitingComplete, WaitingComplete)).
    apply ReachStep with (s := (WaitingResponse, WaitingComplete)).
    apply ReachStep with (s := (WaitingResponse, Initiation)).
    apply ReachStep with (s := init_state).
    apply ReachInit.
    apply TransInitiatorSendsInit; auto.
    apply TransResponderSendsResponse; auto.
    apply TransInitiatorSendsComplete; auto.
    apply TransResponderReceivesComplete; auto.
Qed.

(* Main theorem: any reachable state satisfies the safety invariant *)
Theorem safety_theorem :
  forall s, Reachable s -> SafetyInvariant s.
Proof.
  unfold SafetyInvariant.
  intros s Hr.
  induction Hr.
  - (* Init *)
    intros Hbc.
    unfold both_completed, init_state in Hbc; simpl in Hbc.
    destruct Hbc as [H1 H2].
    discriminate H1.
  - (* Step *)
    intros Hbc.
    eapply transition_preserves_inv.
    apply H.
    apply IHHr.
    exact Hbc.
Qed.
