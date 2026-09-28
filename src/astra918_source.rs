//! Astra918 native USB receiver. Only interface 4 is claimed; UAC and CDC
//! remain owned by the OS and continue independently of this I/Q stream.
//!
//! AST1/ASIQ is documented in Astra918's MIT-licensed `docs/PROTOCOL.md`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nusb::transfer::{Buffer, Bulk, In, Out};
use nusb::{Endpoint, MaybeFuture};
use sdroxide_dsp::Complex32;
use sdroxide_radio::{ControlUpdate, IqSource};
use sdroxide_types::{Astra918Config, Astra918Device};

const VID: u16 = 0xc0de;
const PID: u16 = 0x091a;
const INTERFACE: u8 = 4;
const RECORD: usize = 256;
const FRAME: usize = 2112;
const SAMPLES: usize = 512;
const RATE: f64 = 120_000.0;
const TIMEOUT: Duration = Duration::from_secs(5);

pub fn list() -> Vec<Astra918Device> {
    match nusb::list_devices().wait() {
        Ok(devices) => devices
            .filter(|d| d.vendor_id() == VID && d.product_id() == PID)
            .map(|d| Astra918Device {
                serial: d.serial_number().map(str::to_owned),
                name: d.product_string().unwrap_or("Astra918").to_owned(),
            })
            .collect(),
        Err(e) => {
            tracing::warn!("Astra918 USB enumeration failed: {e}");
            Vec::new()
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub dial: u64,
    pub center: u64,
    pub offset: i32,
    pub rate: u32,
    pub input: u8,
    pub rf_mode: u8,
    pub if_mode: u8,
    pub rf_gain: u8,
    pub if_gain: u8,
    pub capacitor: u16,
    pub lf_gain: u8,
    pub attenuator: u8,
    pub audio_mode: u8,
    pub audio_low: u16,
    pub audio_high: u16,
    pub reference: u8,
    pub gpio: u8,
    pub features: u8,
    pub generation: u32,
    pub streaming: bool,
    pub configured: bool,
}

fn le16(p: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(p[at..at + 2].try_into().unwrap())
}
fn le32(p: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(p[at..at + 4].try_into().unwrap())
}
fn le64(p: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(p[at..at + 8].try_into().unwrap())
}

fn parse_status(p: &[u8]) -> Result<Status> {
    ensure!(p.len() == 128, "Astra918 status must be 128 bytes");
    let s = Status {
        dial: le64(p, 0),
        center: le64(p, 80),
        offset: i32::from_le_bytes(p[88..92].try_into()?),
        rate: le32(p, 16),
        input: p[28],
        rf_mode: p[30],
        if_mode: p[31],
        rf_gain: p[32],
        if_gain: p[33],
        capacitor: le16(p, 76),
        lf_gain: p[78],
        attenuator: p[79],
        audio_mode: p[92],
        audio_low: le16(p, 94),
        audio_high: le16(p, 116),
        reference: p[118],
        gpio: p[119],
        features: p[120],
        generation: le32(p, 36),
        streaming: p[34] != 0,
        configured: p[35] != 0,
    };
    ensure!(s.rate == RATE as u32, "Astra918 returned unsupported sample rate {}", s.rate);
    ensure!(
        s.center as i128 + s.offset as i128 == s.dial as i128,
        "Astra918 dial/center/offset disagree"
    );
    ensure!(
        s.input <= 3
            && s.rf_mode <= 1
            && s.if_mode <= 1
            && s.capacitor <= 4095
            && s.reference <= 1
            && matches!(s.audio_mode, 1 | 2),
        "Astra918 status contains an invalid setting"
    );
    Ok(s)
}

/// The firmware requires the entire demodulated audio passband, plus its
/// transition guard, to remain inside the 120 kHz I/Q window.
fn audio_fits(s: &Status, offset: i64) -> bool {
    let (bottom, top) = if s.audio_mode == 2 {
        (offset + i64::from(s.audio_low), offset + i64::from(s.audio_high))
    } else {
        (offset - i64::from(s.audio_high), offset - i64::from(s.audio_low))
    };
    bottom >= -59_500 && top <= 59_500
}

struct Control {
    out: Endpoint<Bulk, Out>,
    reply: Endpoint<Bulk, In>,
    _iface: nusb::Interface,
    sequence: u32,
    usable: bool,
}

impl Control {
    fn command(&mut self, cmd: u8, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!(self.usable, "Astra918 control framing lost; reconnect receiver");
        ensure!(payload.len() <= 240, "Astra918 command too long");
        self.usable = false;
        self.sequence = self.sequence.wrapping_add(1);
        let mut request = [0u8; RECORD];
        request[..4].copy_from_slice(b"AST1");
        request[4] = 1;
        request[5] = cmd;
        request[8..12].copy_from_slice(&self.sequence.to_le_bytes());
        request[12..14].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        request[16..16 + payload.len()].copy_from_slice(payload);
        // A short control transfer loses record alignment: do not issue another
        // command on this interface until the source is reopened.
        let written = self.out.transfer_blocking(Buffer::from(request), TIMEOUT);
        written.status.map_err(|e| anyhow!("Astra918 control write: {e}"))?;
        ensure!(written.actual_len == RECORD, "short Astra918 command write");
        let answer = self.reply.transfer_blocking(Buffer::new(RECORD), TIMEOUT);
        answer.status.map_err(|e| anyhow!("Astra918 control read: {e}"))?;
        ensure!(answer.actual_len == RECORD, "short Astra918 command reply");
        let a = &answer.buffer[..];
        ensure!(
            &a[..4] == b"AST1" && a[4] == 1 && a[5] == cmd && le32(a, 8) == self.sequence,
            "mismatched Astra918 command reply"
        );
        let length = le16(a, 12) as usize;
        ensure!(length <= 240, "oversized Astra918 reply");
        self.usable = true;
        ensure!(a[6] == 0, "Astra918 rejected command {cmd:#04x}: status {}", a[6]);
        Ok(a[16..16 + length].to_vec())
    }

    fn status(&mut self) -> Result<Status> {
        parse_status(&self.command(0x13, &[])?)
    }
    fn setter(&mut self, cmd: u8, payload: &[u8]) -> Result<Status> {
        parse_status(&self.command(cmd, payload)?)
    }
}

fn iq_reader(mut ep: Endpoint<Bulk, In>, running: Arc<AtomicBool>, tx: SyncSender<Vec<u8>>) {
    while running.load(Ordering::Relaxed) {
        let done = ep.transfer_blocking(Buffer::new(FRAME), Duration::from_millis(100));
        if !done.buffer.is_empty() && tx.try_send(done.buffer.to_vec()).is_err() {
            // A slow client may lose I/Q, never block the USB reader. CAT and
            // UAC are separate endpoints and remain usable.
        }
        if let Err(e) = done.status {
            if !matches!(e, nusb::transfer::TransferError::Cancelled) {
                tracing::warn!("Astra918 I/Q read: {e}");
                break;
            }
        }
    }
}

pub struct Astra918Source {
    control: Control,
    status: Status,
    features: u8,
    serial: String,
    iq_rx: Receiver<Vec<u8>>,
    running: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
    raw: Vec<u8>,
    pending: Vec<Complex32>,
    consumed: usize,
    last_status: Instant,
    reopen: bool,
    settings_dirty: bool,
    last_rx_vfo: u64,
    reported_center: u64,
    reported_dial: u64,
    released: bool,
    last_iq: Instant,
}

impl Astra918Source {
    pub fn open(cfg: &Astra918Config) -> Result<Self> {
        let devices = nusb::list_devices().wait().context("enumerating USB")?;
        let info = devices
            .filter(|d| d.vendor_id() == VID && d.product_id() == PID)
            .find(|d| cfg.serial.as_deref().is_none_or(|want| d.serial_number() == Some(want)))
            .ok_or_else(|| {
                anyhow!("Astra918 receiver not found; choose another serial in Settings > Radio")
            })?;
        let serial = info.serial_number().unwrap_or("unknown").to_owned();
        let device = info.open().wait().context("opening Astra918 USB device")?;
        ensure!(
            device.active_configuration()?.configuration_value() == 1,
            "Astra918 is not configured; reconnect its USB cable"
        );
        let iface = device
            .claim_interface(INTERFACE)
            .wait()
            .context("claiming Astra918 vendor interface; close SDR++ or Astra918 GUI first")?;
        let iq_ep = iface.endpoint::<Bulk, In>(0x85)?;
        let mut control = Control {
            out: iface.endpoint::<Bulk, Out>(0x03)?,
            reply: iface.endpoint::<Bulk, In>(0x84)?,
            _iface: iface,
            sequence: 0,
            usable: true,
        };
        let mut status = control.status()?;
        let features = status.features;
        if status.configured {
            control.command(0x31, &[]).context("stopping stale Astra918 I/Q stream")?;
        }
        // An interrupted prior host can leave a partial frame in endpoint 85.
        // Drain to a quiet interval before accepting ASIQ records.
        let mut iq_ep = iq_ep;
        for _ in 0..32 {
            let d = iq_ep.transfer_blocking(Buffer::new(FRAME), Duration::from_millis(20));
            if d.buffer.is_empty() {
                break;
            }
        }
        if status.configured {
            status = control.setter(0x30, &[]).context("starting Astra918 I/Q stream")?;
            ensure!(status.streaming, "Astra918 did not start its I/Q stream");
        }
        let (tx, iq_rx) = mpsc::sync_channel(32);
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let reader = std::thread::Builder::new()
            .name("astra918-iq".into())
            .spawn(move || iq_reader(iq_ep, flag, tx))?;
        let last_rx_vfo = status.dial;
        let reported_center = status.center;
        let reported_dial = status.dial;
        Ok(Self {
            control,
            status,
            features,
            serial,
            iq_rx,
            running,
            reader: Some(reader),
            raw: Vec::with_capacity(FRAME * 2),
            pending: Vec::with_capacity(SAMPLES),
            consumed: 0,
            last_status: Instant::now(),
            reopen: false,
            settings_dirty: false,
            last_rx_vfo,
            reported_center,
            reported_dial,
            released: false,
            last_iq: Instant::now(),
        })
    }

    pub fn status(&self) -> &Status {
        &self.status
    }
    pub fn features(&self) -> u8 {
        self.features
    }
    fn apply(&mut self, cmd: u8, bytes: &[u8]) -> Result<()> {
        match self.control.setter(cmd, bytes) {
            Ok(mut status) => {
                if status.configured && !status.streaming {
                    status = self.control.setter(0x30, &[])?;
                }
                self.settings_dirty |= self.status != status;
                if !status.streaming && status.configured {
                    tracing::warn!("Astra918 I/Q stopped; reconnecting vendor stream");
                    self.reopen = true;
                }
                self.status = status;
                Ok(())
            }
            Err(e) => {
                self.reopen |= !self.control.usable;
                if self.control.usable {
                    if let Ok(status) = self.control.status() {
                        self.settings_dirty |= self.status != status;
                        self.status = status;
                    }
                }
                Err(e)
            }
        }
    }
    fn next_frame(&mut self) -> bool {
        loop {
            if self.raw.len() < FRAME {
                return false;
            }
            if &self.raw[..4] != b"ASIQ" {
                self.raw.drain(..1);
                continue;
            }
            let frame = &self.raw[..FRAME];
            if frame[4] != 1
                || frame[5] != 0x80
                || le16(frame, 6) != 64
                || le32(frame, 24) != RATE as u32
                || le16(frame, 28) != SAMPLES as u16
            {
                self.raw.drain(..1);
                continue;
            }
            let generation = le32(frame, 8);
            let center = le64(frame, 32);
            // Drop queued records from the old tuning generation. The status
            // query will announce any CAT-initiated retune to the engine.
            if generation != self.status.generation || center != self.status.center {
                self.raw.drain(..FRAME);
                continue;
            }
            self.pending.clear();
            self.last_iq = Instant::now();
            for pair in frame[64..].chunks_exact(4) {
                let i = i16::from_le_bytes([pair[0], pair[1]]) as f32 / 32768.0;
                let q = i16::from_le_bytes([pair[2], pair[3]]) as f32 / 32768.0;
                self.pending.push(Complex32::new(i, q));
            }
            self.consumed = 0;
            self.raw.drain(..FRAME);
            return true;
        }
    }
}

impl IqSource for Astra918Source {
    fn sample_rate(&self) -> f64 {
        RATE
    }
    fn center_hz(&self) -> f64 {
        self.status.center as f64
    }
    fn initial_rx_dial_hz(&self) -> Option<f64> {
        Some(self.status.dial as f64)
    }
    fn set_center_hz(&mut self, hz: f64) -> sdroxide_radio::Result<()> {
        let tune = || -> Result<u64> {
            ensure!(
                hz.is_finite() && hz >= 70_000.0 && hz <= 260_000_000.0,
                "Astra918 center is outside its tuning range"
            );
            let dial = hz.round() as i128 + self.status.offset as i128;
            ensure!((70_000..=260_000_000).contains(&dial), "Astra918 dial outside range");
            Ok(dial as u64)
        };
        let dial = tune().map_err(radio_error)?;
        self.apply(0x20, &dial.to_le_bytes()).map_err(radio_error)
    }
    fn set_rx_dial_hz(&mut self, hz: f64) -> sdroxide_radio::Result<()> {
        if !hz.is_finite() || !(70_000.0..=260_000_000.0).contains(&hz) {
            return Err(sdroxide_radio::RadioError::Msg(
                "Astra918 audio dial outside range".into(),
            ));
        }
        let dial = hz.round() as u64;
        if dial == self.last_rx_vfo {
            return Ok(());
        }
        if dial != self.status.dial {
            let offset = dial as i64 - self.status.center as i64;
            if audio_fits(&self.status, offset) {
                self.apply(0x38, &dial.to_le_bytes()).map_err(radio_error)?;
            } else {
                // SdroXide's DDC can use the whole I/Q span, but firmware
                // audio needs room for its filter at the edge. Move the RF
                // window to this VFO, retaining the existing audio offset.
                let center = dial as i64 - i64::from(self.status.offset);
                self.set_center_hz(center as f64)?;
            }
        }
        self.last_rx_vfo = dial;
        Ok(())
    }
    fn read(&mut self, buf: &mut [Complex32]) -> sdroxide_radio::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.consumed == self.pending.len() {
            if !self.next_frame() {
                match self.iq_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(bytes) => self.raw.extend_from_slice(&bytes),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if self.status.configured && self.last_iq.elapsed() > Duration::from_secs(3)
                        {
                            tracing::warn!("Astra918 I/Q timed out; reconnecting vendor stream");
                            self.reopen = true;
                        }
                        return Ok(0);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        self.reopen = true;
                        return Ok(0);
                    }
                }
                if !self.next_frame() {
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.pending.len() - self.consumed);
        buf[..n].copy_from_slice(&self.pending[self.consumed..self.consumed + n]);
        self.consumed += n;
        Ok(n)
    }
    fn describe(&self) -> String {
        format!("Astra918 {}/120 ksps", self.serial)
    }
    fn poll_control(&mut self) -> Vec<ControlUpdate> {
        if self.last_status.elapsed() < Duration::from_millis(200) {
            return Vec::new();
        }
        self.last_status = Instant::now();
        match self.control.status() {
            Ok(status) => {
                self.settings_dirty |= self.status != status;
                if !status.streaming && status.configured {
                    tracing::warn!("Astra918 I/Q stopped; reconnecting vendor stream");
                    self.reopen = true;
                }
                self.status = status;
            }
            Err(e) => {
                tracing::warn!("Astra918 status poll failed: {e}");
                self.reopen = true;
                return Vec::new();
            }
        }
        let mut updates = Vec::new();
        if self.reported_dial != self.status.dial {
            updates.push(ControlUpdate::Freq(self.status.dial as f64));
            self.reported_dial = self.status.dial;
        }
        if self.reported_center != self.status.center {
            updates.push(ControlUpdate::Center(self.status.center as f64));
            self.reported_center = self.status.center;
        }
        updates
    }
    fn set_device_setting(&mut self, key: &str, value: &str) -> sdroxide_radio::Result<()> {
        self.set_setting(key, value).map_err(radio_error)
    }
    fn take_settings_update(&mut self) -> Option<Vec<sdroxide_types::DeviceSetting>> {
        if !std::mem::take(&mut self.settings_dirty) {
            return None;
        }
        Some(crate::astra918_settings(&self.status, self.features))
    }
    fn needs_reopen(&self) -> bool {
        self.reopen
    }
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        self.running.store(false, Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if self.control.usable {
            let _ = self.control.command(0x31, &[]);
        }
    }
}

fn radio_error(e: anyhow::Error) -> sdroxide_radio::RadioError {
    sdroxide_radio::RadioError::Msg(e.to_string())
}

impl Astra918Source {
    fn set_setting(&mut self, key: &str, value: &str) -> Result<()> {
        let number = || value.parse::<i32>().with_context(|| format!("invalid {key} value"));
        match key {
            "astra.input" => {
                let n = number()?;
                ensure!((0..=3).contains(&n), "input must be 0..3");
                self.apply(0x24, &[n as u8])?
            }
            "astra.rf_mode" | "astra.if_mode" => {
                let n = number()?;
                ensure!((0..=1).contains(&n), "gain mode must be 0 or 1");
                self.apply(0x26, &[u8::from(key == "astra.if_mode"), n as u8])?
            }
            "astra.rf_gain" | "astra.if_gain" | "astra.lf_gain" | "astra.attenuator" => {
                let n = number()?;
                let (block, max) = match key {
                    "astra.rf_gain" => (0, 38),
                    "astra.if_gain" => (1, 31),
                    "astra.lf_gain" => (2, 15),
                    _ => (3, 15),
                };
                ensure!((0..=max).contains(&n), "{key} must be 0..{max}");
                self.apply(0x27, &[block, n as u8])?
            }
            "astra.capacitor" => {
                let n = number()?;
                ensure!((0..=4095).contains(&n), "capacitor must be 0..4095");
                self.apply(0x2d, &(n as u16).to_le_bytes())?
            }
            "astra.reference" => {
                ensure!(self.features & 0x40 != 0, "reference selection unsupported");
                let n = number()?;
                ensure!((0..=1).contains(&n), "reference must be Internal=0 or External=1");
                self.apply(0x3a, &[n as u8])?
            }
            _ if key.starts_with("astra.gpio") => {
                ensure!(self.features & 0x80 != 0, "logical GPIO unsupported");
                let index: u8 = key[10..].parse()?;
                ensure!(index < 8, "GPIO index must be 0..7");
                let n = number()?;
                ensure!((0..=1).contains(&n), "GPIO value must be 0 or 1");
                let mask = 1u8 << index;
                self.apply(0x3b, &[mask, if n == 1 { mask } else { 0 }])?
            }
            "astra.audio_mode" => {
                let n = number()?;
                ensure!((1..=2).contains(&n), "audio mode must be LSB=1 or USB=2");
                self.apply(0x34, &[n as u8])?
            }
            "astra.audio_offset" => {
                let n = number()?;
                let dial = self.status.center as i128 + n as i128;
                ensure!((70_000..=260_000_000).contains(&dial), "audio dial outside range");
                self.apply(0x38, &(dial as u64).to_le_bytes())?
            }
            "astra.audio_filter" => {
                let (lo, hi) = value.split_once(',').ok_or_else(|| anyhow!("use low,high Hz"))?;
                let lo: u16 = lo.trim().parse()?;
                let hi: u16 = hi.trim().parse()?;
                ensure!(lo < hi && hi <= 5000, "audio edges must satisfy 0 <= low < high <= 5000");
                self.apply(0x35, &[lo.to_le_bytes(), hi.to_le_bytes()].concat())?
            }
            "astra.retry" => self.apply(0x37, &[])?,
            "astra.save" => self.apply(0x36, &[])?,
            _ => bail!("unknown Astra918 setting {key}"),
        }
        Ok(())
    }
}

impl Drop for Astra918Source {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_uses_exact_center_and_signed_audio_offset() {
        let mut p = [0u8; 128];
        p[0..8].copy_from_slice(&14_080_000u64.to_le_bytes());
        p[16..20].copy_from_slice(&120_000u32.to_le_bytes());
        p[80..88].copy_from_slice(&14_085_000u64.to_le_bytes());
        p[88..92].copy_from_slice(&(-5_000i32).to_le_bytes());
        p[92] = 1;
        let s = parse_status(&p).unwrap();
        assert_eq!((s.center, s.offset, s.dial), (14_085_000, -5_000, 14_080_000));
        p[88..92].copy_from_slice(&5_000i32.to_le_bytes());
        assert!(parse_status(&p).is_err());
    }

    #[test]
    fn firmware_audio_guard_at_spectrum_edge() {
        let mut s = parse_status(&{
            let mut p = [0u8; 128];
            p[0..8].copy_from_slice(&14_074_000u64.to_le_bytes());
            p[16..20].copy_from_slice(&120_000u32.to_le_bytes());
            p[80..88].copy_from_slice(&14_074_000u64.to_le_bytes());
            p[92] = 2;
            p[94..96].copy_from_slice(&300u16.to_le_bytes());
            p[116..118].copy_from_slice(&3000u16.to_le_bytes());
            p
        })
        .unwrap();
        assert!(audio_fits(&s, 56_500));
        assert!(!audio_fits(&s, 57_000));
        s.audio_mode = 1;
        assert!(audio_fits(&s, -56_500));
        assert!(!audio_fits(&s, -57_000));
    }

    /// Run explicitly with the receiver attached. Uses vendor I/Q only; it
    /// does not alter RF frequency or save settings to flash.
    #[test]
    #[ignore]
    fn astra918_usb_smoke() {
        let mut src = Astra918Source::open(&Astra918Config::default()).unwrap();
        let initial = src.status().clone();
        let mut samples = [Complex32::new(0.0, 0.0); SAMPLES];
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut count = 0;
        while count < 5 && Instant::now() < deadline {
            if src.read(&mut samples).unwrap() > 0 {
                count += 1;
            }
        }
        assert_eq!(count, 5, "no I/Q frames from Astra918");
        assert_eq!(src.control.status().unwrap().dial, initial.dial);
        src.release();
    }
}
