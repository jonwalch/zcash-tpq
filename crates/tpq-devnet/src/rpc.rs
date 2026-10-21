//! Authenticated literal-loopback HTTP only. No proxies, DNS, redirects or retries.
use crate::{require, storage, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_HEADERS: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

pub trait Rpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value>;
}

pub struct HttpRpc {
    address: SocketAddr,
    authorization: String,
}

impl HttpRpc {
    /// `address` is a numeric socket, not a URL. Cookie must be private user:password.
    pub fn new(address: SocketAddr, cookie: &Path) -> Result<Self> {
        require(
            address.ip().is_loopback(),
            "RPC must use a literal loopback socket",
        )?;
        let bytes = storage::read_private(cookie, 4096)?;
        let cookie = std::str::from_utf8(&bytes)?.trim();
        require(
            cookie.contains(':') && !cookie.contains(['\r', '\n']) && cookie.len() >= 3,
            "invalid RPC cookie",
        )?;
        Ok(Self {
            address,
            authorization: STANDARD.encode(cookie),
        })
    }
}

impl Rpc for HttpRpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let body =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
        require(body.len() <= MAX_BODY, "RPC request too large")?;
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))?;
        let mut request = format!("POST / HTTP/1.0\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.address, self.authorization, body.len()).into_bytes();
        request.extend(body);
        let mut written = 0;
        while written < request.len() {
            stream.set_write_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("RPC deadline")?,
            ))?;
            let count = stream.write(&request[written..])?;
            require(count > 0, "RPC request write stopped")?;
            written += count;
        }
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            require(header.len() < MAX_HEADERS, "RPC headers exceed bound")?;
            stream.set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("RPC deadline")?,
            ))?;
            let mut byte = [0];
            stream.read_exact(&mut byte)?;
            header.push(byte[0]);
        }
        let header = std::str::from_utf8(&header)?;
        let mut lines = header.split("\r\n");
        let status = lines.next().ok_or("missing HTTP status")?;
        require(
            status.starts_with("HTTP/1.0 200 ") || status.starts_with("HTTP/1.1 200 "),
            "RPC HTTP status not 200",
        )?;
        let mut length = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or("invalid HTTP header")?;
            require(
                !name.eq_ignore_ascii_case("transfer-encoding"),
                "chunked RPC responses not supported",
            )?;
            if name.eq_ignore_ascii_case("content-length") {
                require(length.is_none(), "duplicate content length")?;
                length = Some(value.trim().parse::<usize>()?);
            }
        }
        let length = length.ok_or("RPC response needs content length")?;
        require(length <= MAX_BODY, "RPC response exceeds bound")?;
        let mut body = vec![0; length];
        let mut offset = 0;
        while offset < length {
            stream.set_read_timeout(Some(
                deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("RPC deadline")?,
            ))?;
            let count = stream.read(&mut body[offset..])?;
            require(count > 0, "truncated RPC response")?;
            offset += count;
        }
        let response: Value = serde_json::from_slice(&body)?;
        require(
            response["id"] == 1 && response.get("error").is_none_or(Value::is_null),
            "RPC returned error or wrong response id",
        )?;
        response
            .get("result")
            .cloned()
            .ok_or_else(|| "missing RPC result".into())
    }
}
