// SPDX-FileCopyrightText: 2026 Matthew Klapman
// SPDX-License-Identifier: Apache-2.0

//! LoRa time-on-air, and the duty-cycle budget computed from it.
//!
//! L5 needs two numbers that both derive from airtime: how long a frame
//! occupies the channel, and whether sending it would exceed the duty budget.
//! This module computes the first and tracks the second.
//!
//! # Where the formula comes from, and why that matters here
//!
//! The time-on-air expression is **Semtech's**, from the SX127x/SX126x
//! datasheets — LoRa PHY arithmetic, published by the radio vendor. It is not
//! Meshtastic's, and nothing here is derived from their implementation. That
//! distinction is the whole point: `docs/DISTRIBUTION.md` allows facts about the
//! wire and forbids their expression, and a PHY formula from the part's own
//! datasheet is as clean a fact as this project has.
//!
//! ```text
//! T_sym      = 2^SF / BW
//! T_preamble = (n_preamble + 4.25) * T_sym
//! n_payload  = 8 + max(0, ceil((8*PL - 4*SF + 28 + 16*CRC - 20*IH)
//!                              / (4*(SF - 2*DE))) * (CR + 4))
//! T_packet   = T_preamble + n_payload * T_sym
//! ```
//!
//! # What it was checked against
//!
//! Two independent corroborations, and they are worth more than either alone:
//!
//! 1. **The preamble lands exactly.** At SF11/BW250 the symbol time is 8.192
//!    ms, so sixteen preamble symbols are 131.07 ms — and
//!    `WIRE_REFERENCE.md` records the reference reporting **131 ms**. That
//!    pins `n_preamble = 16`, which would otherwise have been a guess.
//! 2. **The residual points the right way.** For a 70-byte payload this model
//!    gives 763.9 ms where the reference *simulator* reported 755 ms, +1.18%.
//!    That is not error in the direction that would worry us: the wire
//!    reference separately measured the simulator's bitrate as ~1.2%
//!    optimistic against real silicon. So the formula disagrees with the
//!    simulator by very close to the amount the simulator is already known to
//!    be wrong, and therefore agrees with hardware.
//!
//! **That second point is corroboration, not proof.** It rests on one observed
//! packet. `WIRE_REFERENCE.md` lists airtime among the items still wanting a
//! direct hardware measurement across payload sizes.
//!
//! # Integer arithmetic throughout
//!
//! No floating point. Not for speed — for determinism: two nodes computing
//! different backoff from the same inputs would defeat the purpose, and a
//! duty-cycle budget that drifts with rounding is worse than none. Every
//! operation is `checked_*` or `saturating_*`, per the crate rules.

/// Microseconds. Airtime at these data rates is hundreds of milliseconds, so
/// microsecond resolution leaves ample headroom in a `u32` (about 71 minutes).
pub type Micros = u32;

/// The modem settings that determine time-on-air.
///
/// Constructed explicitly rather than defaulted. A wrong preset silently
/// yields a wrong budget, so there is no `Default` to fall into: the caller
/// states which modem it is modelling.
///
/// **All nine valid presets are measured**, on a stock node on 2026-08-16, and
/// committed as `tests/captures/modem_presets.json`; `WIRE_REFERENCE.md`
/// § item 6 carries the table. This comment previously said only LongFast had
/// been confirmed and that "the other sixteen presets are open" — both were
/// left standing after the measurement landed. There are **nine** valid
/// presets, not seventeen: presets 2 and 10–16 report `name=Invalid` and
/// silently serve LongFast parameters, so a node set out of range does not
/// fail, it quietly runs LongFast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModemParams {
    /// Spreading factor, 7..=12.
    pub spreading_factor: u8,
    /// Bandwidth in Hz, e.g. 250_000.
    pub bandwidth_hz: u32,
    /// Coding-rate index 1..=4, meaning 4/5 through 4/8.
    pub coding_rate: u8,
    /// Preamble length in symbols. Sixteen for Meshtastic, established by the
    /// 131 ms figure above rather than assumed.
    pub preamble_symbols: u16,
    /// Whether a CRC is appended.
    pub crc: bool,
    /// Whether the header is implicit (fixed length). Meshtastic uses an
    /// explicit header, so this is normally `false`.
    pub implicit_header: bool,
    /// Low-data-rate optimisation. Required when symbol time exceeds ~16 ms,
    /// which at these bandwidths means SF11/SF12 on narrow settings.
    pub low_data_rate_optimize: bool,
}

impl ModemParams {
    /// LongFast — the default preset, and the one with two independent
    /// derivations behind it.
    ///
    /// SF11 / BW250 kHz / CR4-5, from `WIRE_REFERENCE.md` § item 6, read off
    /// a real exchange rather than from a table. The other eight valid presets
    /// are measured too and appear below; LongFast is called out because on-air
    /// capture and the preamble-time derivation agree on it independently, and
    /// that agreement is what licenses the derivation for the rest.
    pub const LONGFAST: Self = Self {
        spreading_factor: 11,
        bandwidth_hz: 250_000,
        coding_rate: 1,
        preamble_symbols: 16,
        crc: true,
        implicit_header: false,
        low_data_rate_optimize: false,
    };

    /// LongSlow — preset 1. SF12 / BW125 kHz.
    pub const LONGSLOW: Self = Self {
        spreading_factor: 12,
        bandwidth_hz: 125_000,
        low_data_rate_optimize: true,
        ..Self::LONGFAST
    };

    /// MediumSlow — preset 3. SF10 / BW250 kHz.
    pub const MEDIUMSLOW: Self = Self { spreading_factor: 10, ..Self::LONGFAST };

    /// MediumFast — preset 4. SF9 / BW250 kHz.
    pub const MEDIUMFAST: Self = Self { spreading_factor: 9, ..Self::LONGFAST };

    /// ShortSlow — preset 5. SF8 / BW250 kHz.
    pub const SHORTSLOW: Self = Self { spreading_factor: 8, ..Self::LONGFAST };

    /// ShortFast — preset 6. SF7 / BW250 kHz.
    pub const SHORTFAST: Self = Self { spreading_factor: 7, ..Self::LONGFAST };

    /// LongMod — preset 7. SF11 / BW125 kHz. Narrow enough that the symbol time
    /// reaches 16.384 ms, so low-data-rate optimisation is required.
    pub const LONGMOD: Self = Self {
        bandwidth_hz: 125_000,
        low_data_rate_optimize: true,
        ..Self::LONGFAST
    };

    /// ShortTurbo — preset 8. SF7 / BW500 kHz. The widest bandwidth in use.
    pub const SHORTTURBO: Self =
        Self { spreading_factor: 7, bandwidth_hz: 500_000, ..Self::LONGFAST };

    /// LongTurbo — preset 9. SF11 / BW500 kHz.
    pub const LONGTURBO: Self = Self { bandwidth_hz: 500_000, ..Self::LONGFAST };

    /// Symbol time, in microseconds: `2^SF / BW`.
    ///
    /// Returns `None` for a spreading factor or bandwidth outside the range
    /// the radio supports, rather than producing a plausible wrong number.
    #[must_use]
    pub fn symbol_time_us(&self) -> Option<Micros> {
        if self.spreading_factor < 7 || self.spreading_factor > 12 || self.bandwidth_hz == 0 {
            return None;
        }
        // 2^SF * 1_000_000 / BW. At SF12 this is 4096 * 1e6 = 4.096e9, which
        // overflows u32, so the intermediate is u64.
        let chips: u64 = 1u64.checked_shl(u32::from(self.spreading_factor))?;
        let numer = chips.checked_mul(1_000_000)?;
        let us = numer.checked_div(u64::from(self.bandwidth_hz))?;
        u32::try_from(us).ok()
    }

    /// Time-on-air for a PHY payload of `payload_len` bytes, in microseconds.
    ///
    /// `payload_len` is the full on-air payload — for this stack, the 16-byte
    /// header plus the encrypted body. Returns `None` if the parameters are
    /// out of range or the arithmetic would overflow.
    #[must_use]
    pub fn airtime_us(&self, payload_len: u16) -> Option<Micros> {
        let t_sym = u64::from(self.symbol_time_us()?);

        // T_preamble = (n + 4.25) * T_sym, kept exact by scaling by 4:
        // (4n + 17) * T_sym / 4.
        let n_pre = u64::from(self.preamble_symbols);
        let pre_scaled = n_pre.checked_mul(4)?.checked_add(17)?;
        let t_preamble = pre_scaled.checked_mul(t_sym)?.checked_div(4)?;

        // Payload symbol count. The numerator can go negative for a short
        // payload at a high spreading factor, which is why it is computed
        // signed and clamped at zero rather than allowed to wrap.
        let sf = i64::from(self.spreading_factor);
        let pl = i64::from(payload_len);
        let crc_term: i64 = if self.crc { 16 } else { 0 };
        let ih_term: i64 = if self.implicit_header { 20 } else { 0 };
        let de: i64 = if self.low_data_rate_optimize { 1 } else { 0 };

        let numer = pl
            .checked_mul(8)?
            .checked_sub(sf.checked_mul(4)?)?
            .checked_add(28)?
            .checked_add(crc_term)?
            .checked_sub(ih_term)?;
        let denom = sf.checked_sub(de.checked_mul(2)?)?.checked_mul(4)?;
        if denom <= 0 {
            return None;
        }

        let n_payload: i64 = if numer <= 0 {
            0
        } else {
            // Ceiling division, then scaled by the coding-rate denominator.
            let steps = numer
                .checked_add(denom)?
                .checked_sub(1)?
                .checked_div(denom)?;
            let cr = i64::from(self.coding_rate);
            if !(1..=4).contains(&cr) {
                return None;
            }
            steps.checked_mul(cr.checked_add(4)?)?
        };

        let symbols = n_payload.checked_add(8)?;
        let symbols_u = u64::try_from(symbols).ok()?;
        let t_payload = symbols_u.checked_mul(t_sym)?;

        u32::try_from(t_preamble.checked_add(t_payload)?).ok()
    }
}

/// A duty-cycle budget over a sliding window, owned by the caller.
///
/// # Why this is a caller-owned struct and not a module-level counter
///
/// `docs/DISTRIBUTION.md` forbids mutable global state, because `Send`/`Sync` do
/// not cross an FFI boundary a foreign scheduler calls into. A transmit budget
/// is exactly the shared resource where that would bite: two threads charging
/// one static counter is a data race with regulatory consequences.
///
/// # The window is coarse on purpose
///
/// This is a **fixed window**, not a true sliding one: airtime accumulates
/// until the window elapses, then resets. A real sliding window needs a
/// timestamp per transmission and therefore an allocation or a bounded ring,
/// and the extra fidelity buys little — the failure it prevents is bunching
/// transmissions across a boundary, which at these airtimes is a handful of
/// frames.
///
/// **It is stated rather than hidden because it is a real limitation.** A
/// fixed window can permit up to twice the budget across a boundary in the
/// worst case. Where a regulator requires a strict sliding window, this is not
/// sufficient and the caller needs its own accounting.
#[derive(Debug, Clone, Copy)]
pub struct DutyCycle {
    limit_permille: u16,
    window_us: u64,
    used_us: u64,
    window_started_us: u64,
}

impl DutyCycle {
    /// A budget of `limit_permille` parts per thousand over `window_ms`.
    ///
    /// EU 868 sub-bands are commonly 1% (`10`) or 10% (`100`) over an hour.
    /// **The US 902–928 band this bench runs on is not duty-cycle limited** in
    /// the same way — it is governed by dwell time and frequency hopping — so
    /// this is a voluntary politeness budget there, not a legal one. Encoding
    /// a regulatory assumption here would be wrong; the caller supplies it.
    ///
    /// Returns `None` for a zero-length window or a limit above 1000.
    #[must_use]
    pub fn new(limit_permille: u16, window_ms: u32, now_us: u64) -> Option<Self> {
        if window_ms == 0 || limit_permille > 1000 {
            return None;
        }
        Some(Self {
            limit_permille,
            window_us: u64::from(window_ms).checked_mul(1000)?,
            used_us: 0,
            window_started_us: now_us,
        })
    }

    /// Airtime permitted per window, in microseconds.
    #[must_use]
    pub fn budget_us(&self) -> u64 {
        self.window_us
            .saturating_mul(u64::from(self.limit_permille))
            .checked_div(1000)
            .unwrap_or(0)
    }

    /// Airtime charged in the current window.
    #[must_use]
    pub fn used_us(&self) -> u64 {
        self.used_us
    }

    /// Roll the window forward if it has elapsed.
    ///
    /// Called by both [`Self::would_permit`] and [`Self::charge`] so a caller
    /// cannot observe a stale window by asking in the wrong order.
    fn roll(&mut self, now_us: u64) {
        let elapsed = now_us.saturating_sub(self.window_started_us);
        if elapsed >= self.window_us {
            self.used_us = 0;
            self.window_started_us = now_us;
        }
    }

    /// Whether `airtime_us` more would fit in the budget. Does not charge.
    #[must_use]
    pub fn would_permit(&mut self, now_us: u64, airtime_us: Micros) -> bool {
        self.roll(now_us);
        self.used_us
            .saturating_add(u64::from(airtime_us))
            .le(&self.budget_us())
    }

    /// Charge `airtime_us` against the budget.
    ///
    /// Returns `false` and charges nothing if it would not fit, so a caller
    /// that ignores [`Self::would_permit`] still cannot overrun. Charging is
    /// deliberately fallible rather than saturating: silently accepting a
    /// transmission that breaks the budget is the failure this exists to stop.
    pub fn charge(&mut self, now_us: u64, airtime_us: Micros) -> bool {
        if !self.would_permit(now_us, airtime_us) {
            return false;
        }
        self.used_us = self.used_us.saturating_add(u64::from(airtime_us));
        true
    }
}
