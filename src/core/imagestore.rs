// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

// Image store with hex/bin output helpers.

use std::io::{self, Write};

#[derive(Clone, Copy)]
struct ImageStoreEntry {
    addr: u16,
    value: u8,
}

pub struct ImageStore {
    entries: Vec<ImageStoreEntry>,
    max_entries: usize,
}

impl ImageStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::with_capacity(max_entries),
            max_entries,
        }
    }

    pub fn num_entries(&self) -> usize {
        self.entries.len()
    }

    pub fn store(&mut self, addr: u16, val: u8) {
        if self.entries.len() >= self.max_entries {
            return;
        }
        self.entries.push(ImageStoreEntry { addr, value: val });
    }

    pub fn store_slice(&mut self, addr: u16, values: &[u8]) {
        for (ix, val) in values.iter().enumerate() {
            let next_addr = addr.wrapping_add(ix as u16);
            self.store(next_addr, *val);
        }
    }

    pub fn write_hex_file<W: Write>(&self, mut out: W, go_addr: Option<&str>) -> io::Result<()> {
        let mut line_addr: u16 = 0;
        let mut line_bytes: u8 = 0;
        let mut checksum: u8 = 0;
        let mut hex_data = String::new();
        const LINE_LIMIT: usize = 32;

        for (ix, entry) in self.entries.iter().enumerate() {
            let val = entry.value;
            if line_bytes == 0 {
                line_addr = entry.addr;
                checksum = 0;
                hex_data.clear();
            }
            hex_data.push(hex_digit((val >> 4) & 0x0f));
            hex_data.push(hex_digit(val & 0x0f));
            checksum = checksum.wrapping_add(val);
            line_bytes = line_bytes.wrapping_add(1);

            let next_addr = if ix + 1 < self.entries.len() {
                self.entries[ix + 1].addr
            } else {
                entry.addr
            };

            if (line_bytes as usize) >= LINE_LIMIT || next_addr != entry.addr.wrapping_add(1) {
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

    pub fn write_bin_file<W: Write>(
        &self,
        mut out: W,
        start_addr: u16,
        end_addr: u16,
        fill: u8,
    ) -> io::Result<()> {
        let mut mem = vec![fill; 65536];
        for entry in &self.entries {
            mem[entry.addr as usize] = entry.value;
        }

        let start = start_addr as usize;
        let mut size = end_addr as i32 - start_addr as i32 + 1;
        if size < 0 {
            size = 0;
        }
        let max_len = mem.len().saturating_sub(start);
        let write_size = usize::min(size as usize, max_len);
        out.write_all(&mem[start..start + write_size])?;
        Ok(())
    }
}

fn hex_digit(val: u8) -> char {
    match val {
        0..=9 => (b'0' + val) as char,
        _ => (b'A' + (val - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::ImageStore;

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
        image.write_bin_file(&mut out, 0x000f, 0x0013, 0xff).unwrap();
        assert_eq!(out.len(), 5);
        assert_eq!(out, vec![0xff, 0xaa, 0xff, 0xbb, 0xff]);
    }
}
