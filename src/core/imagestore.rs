// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Image store with hex/bin output helpers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static IMAGE_STORE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct ImageStoreEntry {
    addr: u32,
    value: u8,
}

/// Stores assembled bytes using a temp-file-backed buffer.
///
/// Bytes are appended via `store`/`store_slice` and later emitted as
/// Intel HEX or raw binary output files.
pub struct ImageStore {
    path: PathBuf,
    file: File,
    entries: usize,
    write_error: Option<io::Error>,
}

impl ImageStore {
    /// Create a new image store. `_max_entries` is reserved for future use.
    pub fn new(_max_entries: usize) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let pid = std::process::id();
        let counter = IMAGE_STORE_COUNTER.fetch_add(1, Ordering::Relaxed);
        path.push(format!("opForge-image-{pid}-{nanos}-{counter}.bin"));
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
        {
            Ok(file) => Self {
                path,
                file,
                entries: 0,
                write_error: None,
            },
            Err(err) => Self {
                path,
                file: File::open("/dev/null").unwrap_or_else(|_| {
                    // Fallback: create a file struct that will report errors on use
                    File::open(".").unwrap()
                }),
                entries: 0,
                write_error: Some(err),
            },
        }
    }

    /// Return the number of stored address/byte entries.
    pub fn num_entries(&self) -> usize {
        self.entries
    }

    /// Store a single byte at the given address.
    pub fn store(&mut self, addr: u32, val: u8) {
        if self.write_error.is_some() {
            return;
        }
        let mut buf = [0u8; 5];
        buf[..4].copy_from_slice(&addr.to_be_bytes());
        buf[4] = val;
        if let Err(err) = self.file.write_all(&buf) {
            self.write_error = Some(err);
            return;
        }
        self.entries = self.entries.saturating_add(1);
    }

    /// Store a contiguous slice of bytes starting at `addr`.
    pub fn store_slice(&mut self, addr: u32, values: &[u8]) {
        for (ix, val) in values.iter().enumerate() {
            let next_addr = addr.wrapping_add(ix as u32);
            self.store(next_addr, *val);
        }
    }

    fn read_entries(&self) -> io::Result<Vec<ImageStoreEntry>> {
        let mut reader = BufReader::new(File::open(&self.path)?);
        let mut entries = Vec::new();
        loop {
            let mut buf = [0u8; 5];
            match reader.read_exact(&mut buf) {
                Ok(()) => {
                    let addr = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    entries.push(ImageStoreEntry {
                        addr,
                        value: buf[4],
                    });
                }
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err),
            }
        }
        Ok(entries)
    }

    fn ensure_ready(&self) -> io::Result<()> {
        if let Some(err) = &self.write_error {
            return Err(io::Error::new(err.kind(), err.to_string()));
        }
        self.file.sync_all()?;
        Ok(())
    }

    /// Write an Intel HEX file. Deduplicates by address (last write wins)
    /// and sorts records by address. Optional `go_addr` emits a start-address record.
    pub fn write_hex_file<W: Write>(&self, mut out: W, go_addr: Option<&str>) -> io::Result<()> {
        self.ensure_ready()?;
        let raw_entries = self.read_entries()?;

        // Deduplicate entries by address (last-write-wins), then sort by address.
        let entries = {
            let mut seen = std::collections::HashMap::<u32, u8>::new();
            for entry in &raw_entries {
                seen.insert(entry.addr, entry.value);
            }
            let mut deduped: Vec<ImageStoreEntry> = seen
                .into_iter()
                .map(|(addr, value)| ImageStoreEntry { addr, value })
                .collect();
            deduped.sort_by_key(|e| e.addr);
            deduped
        };

        let mut current_ela: Option<u16> = None;
        let mut line_addr: u16 = 0;
        let mut line_bytes: u8 = 0;
        let mut checksum: u8 = 0;
        let mut hex_data = String::new();
        const LINE_LIMIT: usize = 32;

        for (ix, entry) in entries.iter().enumerate() {
            let ela = (entry.addr >> 16) as u16;
            if current_ela != Some(ela) {
                if ela != 0 || current_ela.is_some() {
                    write_extended_linear_address_record(&mut out, ela)?;
                }
                current_ela = Some(ela);
                line_bytes = 0;
            }

            let val = entry.value;
            if line_bytes == 0 {
                line_addr = (entry.addr & 0xFFFF) as u16;
                checksum = 0;
                hex_data.clear();
            }
            hex_data.push(hex_digit((val >> 4) & 0x0f));
            hex_data.push(hex_digit(val & 0x0f));
            checksum = checksum.wrapping_add(val);
            line_bytes = line_bytes.wrapping_add(1);

            let should_flush = if (line_bytes as usize) >= LINE_LIMIT {
                true
            } else if let Some(next) = entries.get(ix + 1) {
                let next_ela = (next.addr >> 16) as u16;
                next_ela != ela || next.addr != entry.addr.wrapping_add(1)
            } else {
                true
            };

            if should_flush {
                checksum = checksum.wrapping_add(line_bytes);
                checksum = checksum.wrapping_add((line_addr >> 8) as u8);
                checksum = checksum.wrapping_add((line_addr & 0xff) as u8);
                checksum = (!checksum).wrapping_add(1);
                writeln!(
                    out,
                    ":{:02X}{:04X}00{}{:02X}",
                    line_bytes, line_addr, hex_data, checksum
                )?;
                line_bytes = 0;
            }
        }

        if let Some(go) = go_addr {
            let addr = match u16::from_str_radix(go, 16) {
                Ok(v) => v,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid start address",
                    ))
                }
            };
            let mut csum: u8 = 0;
            csum = csum.wrapping_add(4);
            csum = csum.wrapping_add(3);
            csum = csum.wrapping_add((addr >> 8) as u8);
            csum = csum.wrapping_add((addr & 0xff) as u8);
            csum = (!csum).wrapping_add(1);
            writeln!(out, ":040000030000{:04X}{:02X}", addr, csum)?;
        }

        writeln!(out, ":00000001FF")?;
        Ok(())
    }

    /// Write a raw binary file covering `start..=end`, filling gaps with `fill`.
    pub fn write_bin_file<W: Write>(
        &self,
        mut out: W,
        start_addr: u16,
        end_addr: u16,
        fill: u8,
    ) -> io::Result<()> {
        self.ensure_ready()?;
        let entries = self.read_entries()?;

        let start = start_addr as usize;
        let mut size = end_addr as i32 - start_addr as i32 + 1;
        if size < 0 {
            size = 0;
        }
        let alloc_end = start + size as usize;
        let alloc_size = alloc_end.min(65536).saturating_sub(start);
        let mut mem = vec![fill; alloc_size];
        for entry in &entries {
            let Ok(addr16) = u16::try_from(entry.addr) else {
                continue;
            };
            let addr = addr16 as usize;
            if addr >= start && addr < start + alloc_size {
                mem[addr - start] = entry.value;
            }
        }

        out.write_all(&mem)?;
        Ok(())
    }

    /// Return the (min, max) address range of emitted bytes, or `None` if empty.
    pub fn output_range(&self) -> io::Result<Option<(u16, u16)>> {
        self.ensure_ready()?;
        let entries = self.read_entries()?;
        let mut iter = entries.iter();
        let Some(first) = iter.next() else {
            return Ok(None);
        };
        let mut min = first.addr;
        let mut max = first.addr;
        for entry in iter {
            min = min.min(entry.addr);
            max = max.max(entry.addr);
        }
        if min > u16::MAX as u32 || max > u16::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Binary range exceeds 16-bit address space; use linker .output for wide images",
            ));
        }
        Ok(Some((min as u16, max as u16)))
    }

    /// Return all stored `(address, byte)` pairs.
    pub fn entries(&self) -> io::Result<Vec<(u32, u8)>> {
        self.ensure_ready()?;
        let entries = self.read_entries()?;
        Ok(entries
            .into_iter()
            .map(|entry| (entry.addr, entry.value))
            .collect())
    }
}

impl Drop for ImageStore {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn hex_digit(val: u8) -> char {
    match val {
        0..=9 => (b'0' + val) as char,
        _ => (b'A' + (val - 10)) as char,
    }
}

fn write_extended_linear_address_record<W: Write>(out: &mut W, upper: u16) -> io::Result<()> {
    let mut csum: u8 = 0;
    csum = csum.wrapping_add(2); // length
    csum = csum.wrapping_add(4); // record type 04
    csum = csum.wrapping_add((upper >> 8) as u8);
    csum = csum.wrapping_add((upper & 0xff) as u8);
    csum = (!csum).wrapping_add(1);
    writeln!(out, ":02000004{:04X}{:02X}", upper, csum)
}

#[cfg(test)]
mod tests {
    use super::ImageStore;
    use std::io;

    fn parse_hex_byte(s: &str) -> u8 {
        u8::from_str_radix(s, 16).unwrap()
    }

    fn verify_checksum(line: &str) {
        assert!(line.starts_with(':'), "record must start with ':'");
        let bytes = &line[1..];
        let len = parse_hex_byte(&bytes[0..2]) as usize;
        let addr_hi = parse_hex_byte(&bytes[2..4]);
        let addr_lo = parse_hex_byte(&bytes[4..6]);
        let rec_type = parse_hex_byte(&bytes[6..8]);
        let data_start = 8;
        let data_end = data_start + len * 2;
        let checksum = parse_hex_byte(&bytes[data_end..data_end + 2]);

        let mut sum: u8 = 0;
        sum = sum.wrapping_add(len as u8);
        sum = sum.wrapping_add(addr_hi);
        sum = sum.wrapping_add(addr_lo);
        sum = sum.wrapping_add(rec_type);
        for idx in (data_start..data_end).step_by(2) {
            let b = parse_hex_byte(&bytes[idx..idx + 2]);
            sum = sum.wrapping_add(b);
        }
        let expected = (!sum).wrapping_add(1);
        assert_eq!(checksum, expected, "checksum mismatch for {line}");
    }

    #[test]
    fn writes_hex_records_with_valid_checksums() {
        let mut image = ImageStore::new(65536);
        image.store_slice(0x1000, &[0x01, 0x02, 0x03]);
        let mut out = Vec::new();
        image.write_hex_file(&mut out, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.len() >= 2);
        for line in &lines {
            verify_checksum(line);
        }
        assert_eq!(lines.last().copied(), Some(":00000001FF"));
    }

    #[test]
    fn includes_start_segment_record_when_requested() {
        let mut image = ImageStore::new(65536);
        image.store_slice(0x0000, &[0xaa]);
        let mut out = Vec::new();
        image.write_hex_file(&mut out, Some("1234")).unwrap();
        let text = String::from_utf8(out).unwrap();
        let mut has_start = false;
        for line in text.lines() {
            if line.starts_with(":04000003") {
                has_start = true;
                verify_checksum(line);
            }
        }
        assert!(has_start);
    }

    #[test]
    fn write_bin_respects_range_and_fill() {
        let mut image = ImageStore::new(65536);
        image.store(0x0010, 0xaa);
        image.store(0x0012, 0xbb);
        let mut out = Vec::new();
        image
            .write_bin_file(&mut out, 0x000f, 0x0013, 0xff)
            .unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out, vec![0xff, 0xaa, 0xff, 0xbb, 0xff]);
    }

    #[test]
    fn write_hex_emits_extended_linear_address_for_wide_addresses() {
        let mut image = ImageStore::new(65536);
        image.store(0x123456, 0xaa);
        image.store(0x123457, 0xbb);
        let mut out = Vec::new();
        image.write_hex_file(&mut out, None).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(":020000040012"));
        assert!(text.contains(":02345600AABB"));
    }

    #[test]
    fn output_range_rejects_wide_addresses_for_bin_cli() {
        let mut image = ImageStore::new(65536);
        image.store(0x010000, 0xaa);
        let err = image
            .output_range()
            .expect_err("expected out-of-range error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
