// SPDX-FileCopyrightText: 2026 The tetherpoint Authors
// SPDX-License-Identifier: Apache-2.0

//! Frames for the hardware bench to transmit.
//!
//! An integration test rather than a unit one, and not for tidiness: the crate
//! is unconditionally `#![no_std]`, so a `#[cfg(test)]` module inside it has no
//! `println!` and no `std::env` to read an override from. A test crate has
//! both, and `tools/check_rust_rules.sh` already exempts `tests/` paths because
//! a test may panic -- that is what an assertion is.

use tethermesh::channel;
use tethermesh::crypto::{expand_psk, Psk};
use tethermesh::frame;
use tethermesh::header::Header;
use tethermesh::message::Data;
use tethermesh_groups::{
    open_in_place, parse, seal, Binding, GroupEpoch, MsgType, HEADER_BYTES, PORTNUM,
};

/// Emit a complete extension frame for the bench to transmit.
///
/// L7's gate has a clause only hardware can answer: *an unmodified reference
/// node relays authenticated extension traffic **without reading it***. Every
/// other clause is settled above, in software — a forged sender fails the tag,
/// a relayed frame still verifies, an earlier epoch key cannot read a later
/// message. Those are properties of the construction. Whether a stock node
/// carries a portnum it has never heard of is a property of *their* firmware,
/// and no amount of host testing can establish it.
///
/// So this prints a frame rather than asserting one. The envelope rides inside
/// an ordinary `Data` on `PORTNUM` 256, channel-encrypted like any other
/// traffic, because that is the whole design: to a relay it is bytes.
///
/// The channel key is the published default, deliberately. The extension's
/// confidentiality comes from the group key sealing the envelope, not from the
/// channel — so a frame anyone on the default channel can decrypt and still not
/// read is exactly the demonstration wanted.
#[test]
fn emit_suite_frame_for_the_bench() {
    // Overridable: a repeated (from, id) is dropped mesh-wide by duplicate
    // suppression, which is indistinguishable from never arriving. That has
    // cost this bench two debugging cycles.
    let from: u32 = std::env::var("SUITE_FROM").ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x3280_70b9);
    let id: u32 = std::env::var("SUITE_ID").ok()
        .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x0bad_5117);

    let Psk::Aes128(chan_key) = expand_psk(&[0x01]).expect("default psk") else {
        panic!("expected an AES-128 channel key")
    };

    // The header must exist before the seal, because the AAD is the invariant
    // subset of these very bytes -- and it must be the SAME header that goes on
    // the wire, or the tag verifies against something nobody sent.
    let header = Header {
        to: 0xFFFF_FFFF,
        from,
        id,
        hop_limit: 3,
        hop_start: 3,
        channel: channel::channel_hash(b"LongFast", &chan_key),
        relay_node: (from & 0xFF) as u8,
        ..Header::default()
    };
    let hdr_bytes = header.encode();

    let group_key = [0x42u8; 32];
    let mut envelope = [0u8; 128];
    let group = GroupEpoch { group_key: &group_key, group_id: 0xCAFE, epoch: 0 };
    let binding = Binding { header: &hdr_bytes, from, id };
    let n = seal(&group, &binding, MsgType::Data, b"suite-relay-probe", &mut envelope)
        .expect("seal");

    let data = Data { portnum: PORTNUM, payload: &envelope[..n], ..Data::default() };
    let mut plain = [0u8; 200];
    let plen = data.encode(&mut plain).expect("Data encode");

    let mut fb = [0u8; frame::MAX_FRAME];
    let flen = frame::encode(&header, &plain[..plen], &chan_key, 0, &mut fb)
        .expect("frame encode");

    // Prove it round-trips under our own reader before spending airtime on it.
    {
        let mut back = fb[..flen].to_vec();
        let (h2, pl) = frame::decode_in_place(&mut back, &chan_key, 0).expect("decode");
        let d2 = Data::decode(pl).expect("Data decode");
        assert_eq!(d2.portnum, PORTNUM);
        let env = parse(d2.payload).expect("envelope parses");
        assert_eq!(env.group_id, 0xCAFE);
        // The WHOLE envelope, not env.sealed: open_in_place re-reads the
        // version, type, group and epoch from the front of the buffer, which is
        // what makes those fields authenticated rather than merely present.
        let mut whole = d2.payload.to_vec();
        let h2_bytes = h2.encode();
        let back_binding = Binding { header: &h2_bytes, from: h2.from, id: h2.id };
        let opened = open_in_place(&group_key, &back_binding, &mut whole)
            .expect("our own frame must open under our own reader");
        assert_eq!(&whole[HEADER_BYTES..HEADER_BYTES + opened], b"suite-relay-probe",
                   "our own frame must open to what went in");
    }

    println!("SUITE_FRAME {}",
             fb[..flen].iter().map(|b| format!("{b:02x}")).collect::<String>());
    println!("SUITE_PORTNUM {PORTNUM} SUITE_LEN {flen} SUITE_FROM {from:08x} SUITE_ID {id:08x}");
}
