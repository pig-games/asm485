// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Erik van der Tier

use std::io::{self, BufRead, BufReader, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::lsp::session::{LspSession, OutboundMessage};

pub fn run_stdio() -> io::Result<()> {
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());
    let inbound_rx = spawn_stdin_reader();
    let mut session = LspSession::new();

    loop {
        let async_outbound = session.poll_async_notifications();
        for item in async_outbound {
            write_lsp_message(&mut writer, &outbound_to_json(item))?;
        }
        writer.flush()?;

        match inbound_rx.recv_timeout(Duration::from_millis(25)) {
            Ok(InboundMessage::Payload(message)) => {
                let outbound = session.handle_message(&message);
                for item in outbound {
                    write_lsp_message(&mut writer, &outbound_to_json(item))?;
                }
                writer.flush()?;
                if session.should_exit() {
                    break;
                }
            }
            Ok(InboundMessage::Eof) => break,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

enum InboundMessage {
    Payload(Value),
    Eof,
}

fn spawn_stdin_reader() -> mpsc::Receiver<InboundMessage> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        loop {
            match read_lsp_message(&mut reader) {
                Ok(Some(value)) => {
                    if tx.send(InboundMessage::Payload(value)).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    let _ = tx.send(InboundMessage::Eof);
                    break;
                }
                Err(_) => {
                    let _ = tx.send(InboundMessage::Eof);
                    break;
                }
            }
        }
    });
    rx
}

fn read_lsp_message(reader: &mut impl BufRead) -> io::Result<Option<Value>> {
    let mut content_length: Option<usize> = None;

    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.eq_ignore_ascii_case("Content-Length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }

    let Some(length) = content_length else {
        // Missing Content-Length header — skip this message and try reading the
        // next one rather than treating it as EOF.
        return read_lsp_message(reader);
    };
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let value = serde_json::from_slice::<Value>(&body).unwrap_or_else(|_| json!({}));
    Ok(Some(value))
}

fn write_lsp_message(writer: &mut impl Write, payload: &Value) -> io::Result<()> {
    let body = payload.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body)
}

fn outbound_to_json(message: OutboundMessage) -> Value {
    match message {
        OutboundMessage::Response { id, result } => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        }),
        OutboundMessage::Error { id, code, message } => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": message,
            }
        }),
        OutboundMessage::Notification { method, params } => json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }),
    }
}
