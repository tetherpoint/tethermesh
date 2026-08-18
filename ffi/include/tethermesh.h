/*
 * SPDX-FileCopyrightText: 2026 The tetherpoint Authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * tethermesh.h — C interface to the tethermesh protocol library.
 *
 * HAND-WRITTEN, AND WHAT THAT COSTS
 * ---------------------------------
 * cbindgen is not available in this environment, so this header is maintained
 * by hand against tmffi/src/lib.rs. A hand-written header drifts silently: a
 * field added on the Rust side shifts every offset after it, and C then reads
 * garbage that looks like a protocol bug rather than a build problem.
 *
 * tm_check_layout() exists because of that. Call it once at startup, passing
 * this header's own sizeof values; a mismatch is reported instead of
 * misbehaving. It compares sizes, so it catches a field added, removed or
 * resized and does NOT catch two same-width fields swapped. Install cbindgen
 * and generate this file when you can -- the gate is a mitigation, not a fix.
 *
 * WHAT THIS LIBRARY IS AND IS NOT
 * -------------------------------
 * It is the Meshtastic protocol: framing, channel crypto, and the routing
 * decision. It is not a radio driver, has no clock, allocates nothing, and
 * holds no global state. Everything time-dependent takes `now_us` as an
 * argument because a no_std library cannot portably know the time, and a hidden
 * clock would be untestable.
 *
 * MEMORY AND STACK
 * ----------------
 * The context is yours to place. tm_ctx_size() reports how much; putting it in
 * .bss means the linker checks the budget, where a task-stack local means a
 * stack overflow discovered in the field. On a Cortex-M with no MPU region that
 * overflow corrupts an adjacent task's memory and surfaces later as something
 * unrelated.
 *
 * Budget ~1 KB of stack for this library's own call depth, measured at 696
 * bytes worst case in CCM decrypt. FreeRTOS's configMINIMAL_STACK_SIZE of 512
 * bytes is smaller than one decrypt.
 *
 * One task per context needs no lock. Sharing one needs yours; nothing here can
 * enforce it, because Send/Sync do not cross this boundary.
 */

#ifndef TETHERMESH_H
#define TETHERMESH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Status codes ──────────────────────────────────────────────────────────*/
#define TM_OK             0
#define TM_E_ARG         -1
#define TM_E_ABI         -2   /* version or layout mismatch */
#define TM_E_SHORT       -3   /* frame too short to be one */
#define TM_E_BAD_KEY_LEN -4
#define TM_E_BAD_INDEX   -5
#define TM_E_TOO_AGGRESSIVE -6  /* retry policy exceeds the measured ceiling */

/* Bumped on any change to a signature, struct layout, or enum value below.
 * Compare against tm_abi_version() at startup. */
#define TM_ABI_VERSION 4u

uint32_t tm_abi_version(void);

/* Pass this header's own sizeofs. See the note at the top of this file. */
int32_t tm_check_layout(size_t sizeof_rx, size_t sizeof_key, size_t sizeof_user);

/* ── Channel keys ──────────────────────────────────────────────────────────
 *
 * A distinct type on purpose. Meshtastic's PSK field is polymorphic: 0 bytes
 * means no crypto, 16 or 32 bytes is a key, and 1 byte is a shorthand INDEX
 * where 1 names the default key and 2..10 name it with 1..9 added to its last
 * byte. All are legitimate protocol inputs.
 *
 * A function taking (const uint8_t *, size_t) cannot tell them apart, and the
 * failure is silent: the first consumer written against this library passed the
 * index {1} where the expanded key was wanted and computed channel hash 0x0b
 * instead of 0x08 -- wrong, unreported, and on the most common channel on the
 * network. So there is no such function. Build a key by naming which form you
 * have, and pass tm_key_t everywhere after. */
typedef struct {
    uint8_t bytes[16];
} tm_key_t;

/* Expand the 1-byte shorthand. index 1..10; 0 means "no crypto" and is
 * rejected rather than silently yielding a key. */
int32_t tm_key_from_index(uint8_t index, tm_key_t *out);

/* Take an explicit key. len must be 16 or 32 -- anything else is an error, not
 * a truncation. */
int32_t tm_key_from_bytes(const uint8_t *psk, size_t len, tm_key_t *out);

/* Channel hash.
 *
 * `name` is the MODEM PRESET name, not whatever a config message carries.
 * Proto3 omits defaults, so the primary channel's name is absent on the wire,
 * and hashing the empty string yields 0x02 where real traffic shows 0x08. For
 * the default channel pass "LongFast". */
uint8_t tm_channel_hash(const uint8_t *name, size_t name_len, const tm_key_t *key);

/* ── Context ───────────────────────────────────────────────────────────────*/

typedef struct tm_ctx tm_ctx_t;   /* opaque; size from tm_ctx_size() */

size_t tm_ctx_size(void);
size_t tm_ctx_align(void);

/* `abi` must be TM_ABI_VERSION as this header defines it. */
int32_t tm_ctx_init(tm_ctx_t *ctx, uint32_t abi, uint32_t node_num);

/* ── Receive ───────────────────────────────────────────────────────────────*/

#define TM_SUPPRESSED_NONE              0
#define TM_SUPPRESSED_DUPLICATE         1
#define TM_SUPPRESSED_HOP_LIMIT         2
#define TM_SUPPRESSED_RELAYED_BY_OTHER  3
#define TM_SUPPRESSED_DUTY_BUDGET       4

typedef struct {
    uint32_t from;
    uint32_t to;
    uint32_t id;
    uint8_t  hop_limit;
    uint8_t  want_ack;
    uint8_t  channel_hash;
    uint8_t  duplicate;
    uint8_t  relay;               /* 1 = rebroadcast after waiting */
    uint8_t  relay_window_slots;  /* draw uniformly in [0, this) */
    uint8_t  relay_hop_limit;     /* already decremented */
    uint8_t  suppressed;          /* TM_SUPPRESSED_* when relay == 0 */
} tm_rx_t;

/* Observe a received frame: parse the header, record it in history, decide
 * whether to relay.
 *
 * `snr_q4` is signed quarter-dB -- the unit the radio reports AND the unit the
 * protocol carries, so nothing rescales it and there is no conversion to get
 * backwards.
 *
 * relay_window_slots is a WINDOW, not a delay. Draw uniformly in
 * [0, relay_window_slots) and wait that many slots. Waiting the value verbatim
 * makes every node that heard the frame transmit at the same instant, which is
 * how a mesh collides with itself.
 *
 * Takes no key, deliberately: relaying does not require decrypting, and stock
 * nodes are observed forwarding traffic on channels they cannot read.
 *
 * `heard_relayed` is yours to determine and cannot be inferred here: it means
 * "I already have this frame queued for relay and have now heard someone else
 * send it." This library holds no pending-transmission set -- it has neither a
 * clock nor a radio. Passing 0 always leaves should_relay's "transmit if nobody
 * else did" clause unenforceable and AlreadyRelayedByAnother unreachable. */
int32_t tm_rx_observe(tm_ctx_t *ctx,
                      const uint8_t *frame, size_t frame_len,
                      int16_t snr_q4,
                      uint32_t airtime_us,
                      uint64_t now_us,
                      uint8_t heard_relayed,
                      tm_rx_t *out);

/* ── Transmit ──────────────────────────────────────────────────────────────*/

/* Encode a broadcast text message into a ready-to-send frame. Returns the frame
 * length, or negative on error.
 *
 * `to` is 0xFFFFFFFF for a broadcast, or a node number for a direct message.
 * Text is portnum 1 (TEXT_MESSAGE_APP).
 *
 * `want_ack` asks the destination to acknowledge, and is meaningful only when
 * addressed -- a broadcast nobody owns is a broadcast nobody acknowledges, and
 * setting it there asks a whole mesh to reply at once.
 *
 * `id` must not repeat. Every receiver keys duplicate suppression on
 * (from, id), so a reused identifier is silently dropped by everyone that saw
 * the first one -- the failure looks like a radio problem and is not one.
 *
 * hop_start is set equal to hop_limit, which is what an originating node does;
 * the pair is how receivers work out how far a frame has travelled. */
int32_t tm_text_encode(uint32_t from, uint32_t to, uint32_t id,
                       uint8_t hop_limit, uint8_t channel_hash,
                       uint8_t want_ack,
                       const tm_key_t *key,
                       const uint8_t *text, size_t text_len,
                       uint8_t *out, size_t out_cap);

/* Patch a received frame in place for rebroadcast.
 *
 * Changes hop_limit (to tm_rx_t.relay_hop_limit) and relay_node (to the low
 * byte of our node number). Everything else -- id, from, the encrypted body --
 * is carried verbatim. That is what makes it a forward rather than a new
 * packet: rewriting from or id would defeat duplicate suppression across the
 * entire mesh and multiply the frame instead of relaying it. */
int32_t tm_relay_prepare(uint8_t *frame, size_t frame_len,
                         uint8_t relay_hop_limit, uint32_t our_node_num);

/* Record a packet we originated, so it is suppressed if it returns.
 *
 * Transmitting records nothing in history, so our own packet coming back from
 * someone else's relay reports duplicate=0 and only a `from != our node` check
 * prevents a loop -- one check deep, for a failure that multiplies traffic
 * across an entire mesh. Call this after transmitting and the ordinary
 * duplicate machinery covers it too. */
int32_t tm_note_originated(tm_ctx_t *ctx, uint32_t from, uint32_t id);

/* Decrypt in place; `payload` points into `frame` afterwards. Separate from
 * tm_rx_observe because only this half needs a key. */
int32_t tm_frame_decrypt(uint8_t *frame, size_t frame_len,
                         const tm_key_t *key,
                         const uint8_t **payload, size_t *payload_len);

/* ── Delivery: acknowledgement and retransmission ──────────────────────────
 *
 * LoRa gives forward error correction and a CRC -- it repairs some corrupted
 * symbols and detects the rest -- and NO ARQ whatsoever. A frame lost beyond
 * FEC's reach is lost silently. Flood routing raises the odds of arrival by
 * redundancy; that is not delivery confirmation, and treating it as one is the
 * mistake this section exists to prevent.
 *
 * THE RETRY POLICY IS A CEILING, NEVER A TARGET. Retransmission spends SHARED
 * airtime, and on a flood mesh every retry is rebroadcast by every neighbour
 * that hears it -- the cost multiplies by local node count and is borne by
 * nodes that get nothing from it. tm_outbox_init REFUSES a policy more
 * aggressive than the measured ceiling rather than clamping it, because a clamp
 * leaves the caller believing it configured something it did not. */

typedef struct tm_outbox tm_outbox_t;  /* opaque; size from tm_outbox_size() */

size_t tm_outbox_size(void);
size_t tm_outbox_align(void);

/* Pass max_attempts = 0 and interval_us = 0 for the measured ceiling: 3
 * attempts, 7 s apart. Anything more aggressive returns TM_E_TOO_AGGRESSIVE. */
int32_t tm_outbox_init(tm_outbox_t *ob, uint32_t abi,
                       uint8_t max_attempts, uint32_t interval_us);

/* Track a frame ALREADY transmitted once; the first send is the caller's and
 * its airtime is the caller's to charge. TM_E_SHORT when every slot is in use. */
int32_t tm_outbox_track(tm_outbox_t *ob, const uint8_t *frame, size_t frame_len,
                        uint64_t now_us);

/* 1 if an entry matched, 0 if none did. Zero is ORDINARY, not an error: the
 * acknowledgement may be for a frame already retired, or for another node. */
int32_t tm_outbox_acknowledge(tm_outbox_t *ob, uint32_t request_id);

int32_t tm_outbox_pending(const tm_outbox_t *ob);

/* 1 and fills the outputs when an entry has exhausted every attempt, 0 when
 * none has. Call until it returns 0. Giving up is REPORTED rather than dropped:
 * "this was never acknowledged" is the only evidence available that a frame did
 * not arrive. */
int32_t tm_outbox_reap(tm_outbox_t *ob, uint64_t now_us,
                       uint32_t *out_from, uint32_t *out_id);

/* Length of the next frame due, or 0 when nothing is due / all exhausted / the
 * duty budget would not permit it.
 *
 * A CALLER THAT TAKES A FRAME MUST TRANSMIT IT -- the attempt is marked and the
 * next scheduled by this call, so discarding the result silently consumes a
 * retry. The duty budget is deliberately NOT charged here; the caller charges
 * on actual transmission, because charging here would bill a node for a frame
 * it had not sent. */
int32_t tm_outbox_next_due(tm_outbox_t *ob, tm_ctx_t *ctx,
                           uint64_t now_us, uint32_t airtime_us,
                           uint8_t *out, size_t out_cap, uint8_t *out_attempt);

/* 1 if this decrypted payload is an acknowledgement. out_status is the Routing
 * status; 0 is acceptance. A REJECTION RETIRES THE ENTRY EXACTLY AS AN
 * ACCEPTANCE DOES -- either way no further retransmission will help -- so it is
 * reported for logging, not for the outbox to act on differently. */
int32_t tm_acknowledges(const uint8_t *payload, size_t payload_len,
                        uint32_t *out_request_id, uint32_t *out_status);

/* Whether a received frame is addressed to us and asks to be acknowledged.
 * Header only; the body does not need decrypting to answer it. */
int32_t tm_wants_ack(const uint8_t *frame, size_t frame_len, uint32_t our_node_num);

/* Build and encrypt an acknowledgement of request_id. Returns frame length.
 *
 * Two measured facts are baked in, neither obvious. The success payload is the
 * two bytes 18 00 -- Routing field 3 encoded EXPLICITLY, where proto3 would
 * omit a zero varint, so an acknowledgement built from first principles carries
 * an empty payload and on the evidence would not be recognised. And the reply
 * travels CHANNEL-encrypted even when acknowledging a PKI message: it does not
 * inherit the request's encryption mode, which fails looking like a radio
 * fault. want_ack is deliberately not set -- acknowledging an acknowledgement
 * spends shared airtime for no delivery benefit. */
int32_t tm_ack_encode(uint32_t from, uint32_t to, uint32_t id,
                      uint32_t request_id, uint8_t hop_limit,
                      uint8_t channel_hash, const tm_key_t *key,
                      uint8_t *out, size_t out_cap);

/* ── Identity: publishing a public key ─────────────────────────────────────
 *
 * A node that publishes no public key CANNOT BE SENT A DIRECT MESSAGE AT ALL.
 * The sender refuses to fall back to channel encryption for a destination whose
 * key it does not hold, and NAKs the packet locally -- so the failure never
 * reaches the air, and presents as a dead link rather than as a missing key. */

/* Derive the X25519 public key from a 32-byte private key.
 *
 * private_len must be 32; any other length is an error, never a truncation.
 * The scalar is clamped internally per RFC 7748, so you may store the raw 32
 * bytes you drew. Clamping is idempotent; NOT clamping computes a different
 * function rather than a weaker one.
 *
 * THIS DERIVES. IT DOES NOT GENERATE. Where the private key comes from and
 * where it is kept are yours to decide: a portable no_std library has no
 * entropy source and no storage, and a tm_keygen() quietly using a weak one
 * would put a security-critical choice behind an interface that cannot honour
 * it. Draw it from a hardware RNG you have checked, and persist it -- an
 * identity that changes every boot is a new node to every peer that saw the
 * old one. */
int32_t tm_x25519_public(const uint8_t *private_key, size_t private_len,
                         uint8_t *out, size_t out_cap);

/* What a node publishes about itself.
 *
 * Pointer/length pairs because every field is variable-length on the wire; a
 * fixed array would force this header to invent a maximum the protocol does not
 * define. A NULL pointer or zero length OMITS the field, which is what proto3
 * does with a default.
 *
 * macaddr is the trap. It has been deprecated since 2.1.x and firmware 2.7.26
 * still puts it on the wire as six zero bytes in every User in the corpus, so a
 * User that drops it re-encodes SHORTER than the reference produces. Pass the
 * six zero bytes. Deprecated in the schema is not absent from the wire. */
typedef struct {
    const uint8_t *id;            /* conventionally '!' + node number in hex */
    size_t         id_len;
    const uint8_t *long_name;
    size_t         long_name_len;
    const uint8_t *short_name;    /* conventionally four characters */
    size_t         short_name_len;
    const uint8_t *public_key;    /* 32 bytes from tm_x25519_public() */
    size_t         public_key_len;
    const uint8_t *macaddr;       /* six bytes; read the note above */
    size_t         macaddr_len;
    uint32_t       hw_model;
    uint32_t       role;
} tm_user_t;

/* Build and encrypt a NODEINFO_APP frame announcing this node. Returns length.
 *
 * The on-air payload for this port is a BARE User -- not a NodeInfo wrapping
 * one -- which is what the corpus shows and what a stock node parses.
 *
 * Broadcast with to = 0xFFFFFFFF. When answering another node's request,
 * address it to the asker and leave want_response clear, so two nodes cannot
 * ask each other in a loop.
 *
 * relay_node is stamped with the low byte of `from`, which is what an
 * originating node does. */
int32_t tm_nodeinfo_encode(uint32_t from, uint32_t to, uint32_t id,
                           uint8_t hop_limit, uint8_t channel_hash,
                           uint8_t want_response,
                           const tm_key_t *key, const tm_user_t *user,
                           uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif /* TETHERMESH_H */
