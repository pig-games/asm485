use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub struct LspTestClient {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Value>,
    pending: VecDeque<Value>,
    next_id: u64,
}

impl LspTestClient {
    pub fn spawn() -> io::Result<Self> {
        let bin_path = lsp_binary_path();
        let mut child = Command::new(bin_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        thread::sleep(Duration::from_millis(20));
        let _ = child.try_wait()?;

        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let rx = spawn_reader_thread(stdout);

        Ok(Self {
            child,
            stdin,
            rx,
            pending: VecDeque::new(),
            next_id: 1,
        })
    }

    pub fn initialize(&mut self, initialization_options: Value) -> Value {
        self.request(
            "initialize",
            json!({
                "processId": std::process::id(),
                "rootUri": Value::Null,
                "capabilities": {},
                "initializationOptions": initialization_options,
            }),
        )
    }

    pub fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.send_message(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .expect("send request");
        self.wait_for_response(id, Duration::from_secs(5))
            .expect("request response")
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        self.send_message(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }))
        .expect("send notification");
    }

    pub fn wait_for_notification(&mut self, method: &str, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(index) = self.pending.iter().position(|msg| {
                msg.get("method")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name == method)
            }) {
                return self.pending.remove(index);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .rx
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(message) => self.pending.push_back(message),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    pub fn wait_for_publish_diagnostics(&mut self, uri: &str, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(index) = self.pending.iter().position(|msg| {
                msg.get("method")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name == "textDocument/publishDiagnostics")
                    && msg
                        .get("params")
                        .and_then(|params| params.get("uri"))
                        .and_then(Value::as_str)
                        .is_some_and(|value| value == uri)
            }) {
                return self
                    .pending
                    .remove(index)
                    .and_then(|msg| msg.get("params").cloned());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .rx
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(message) => self.pending.push_back(message),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    pub fn shutdown(&mut self) {
        let _ = self.request("shutdown", Value::Null);
        let _ = self.wait_for_exit(Duration::from_secs(2));
    }

    fn wait_for_response(&mut self, id: u64, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(index) = self
                .pending
                .iter()
                .position(|msg| message_id(msg) == Some(id))
            {
                let message = self.pending.remove(index)?;
                return Some(extract_result_or_error(message));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self
                .rx
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(message) => {
                    if message_id(&message) == Some(id) {
                        return Some(extract_result_or_error(message));
                    }
                    self.pending.push_back(message);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
        None
    }

    fn send_message(&mut self, value: &Value) -> io::Result<()> {
        let body = value.to_string();
        write!(self.stdin, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
        self.stdin.flush()
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(Some(_)) = self.child.try_wait() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for LspTestClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn path_to_file_uri(path: &Path) -> String {
    format!("file://{}", percent_encode(path.to_string_lossy().as_ref()))
}

fn lsp_binary_path() -> PathBuf {
    let from_env = option_env!("CARGO_BIN_EXE_opforge-lsp")
        .map(PathBuf::from)
        .or_else(|| option_env!("CARGO_BIN_EXE_opforge_lsp").map(PathBuf::from));
    from_env.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/debug/opforge-lsp")
    })
}

fn spawn_reader_thread(stdout: ChildStdout) -> Receiver<Value> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let message = read_lsp_message(&mut reader);
            match message {
                Ok(Some(value)) => {
                    if tx.send(value).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
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
        return Ok(None);
    };
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let value = serde_json::from_slice::<Value>(&body).unwrap_or_else(|_| json!({}));
    Ok(Some(value))
}

fn message_id(value: &Value) -> Option<u64> {
    value.get("id").and_then(Value::as_u64)
}

fn extract_result_or_error(message: Value) -> Value {
    if let Some(result) = message.get("result") {
        return result.clone();
    }
    if let Some(error) = message.get("error") {
        return error.clone();
    }
    Value::Null
}

fn percent_encode(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '~' | ':') {
            out.push(c);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}
