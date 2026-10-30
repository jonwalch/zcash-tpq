//! Explicit cookie or trusted-gateway literal-loopback HTTP. No proxies, DNS,
//! redirects, retries or authentication fallback.
use crate::{require, storage, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_BODY: usize = 2 * 1024 * 1024;
const LARGE_HEX_BODY: usize = 40_100_000;
const MAX_HEADERS: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

pub trait Rpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value>;
}

pub struct HttpRpc {
    address: SocketAddr,
    cookie: Option<PathBuf>,
}

impl HttpRpc {
    /// `address` is a numeric socket, not a URL. Cookie must be private user:password.
    pub fn new(address: SocketAddr, cookie: &Path) -> Result<Self> {
        require(
            address.ip().is_loopback() && address.port() != 0,
            "RPC must use a nonzero literal loopback socket",
        )?;
        let rpc = Self {
            address,
            cookie: Some(cookie.to_owned()),
        };
        rpc.authentication()?;
        Ok(rpc)
    }

    /// Trust only an explicitly established local gateway, such as `zdn connect`.
    /// No node cookie is read or forwarded. Seed bootstrap requires direct cookie
    /// mode: participant gateways cannot submit blocks or administer the node.
    pub fn trusted_local_gateway(address: SocketAddr) -> Result<Self> {
        require(
            address.ip().is_loopback() && address.port() != 0,
            "RPC must use a nonzero literal loopback socket",
        )?;
        Ok(Self {
            address,
            cookie: None,
        })
    }

    fn authentication(&self) -> Result<String> {
        let Some(path) = &self.cookie else {
            return Ok(String::new());
        };
        // Reopen for every operation. Invalid or rotated-away credentials must
        // fail before connecting, not select unauthenticated gateway mode.
        let bytes = storage::read_private(path, 4096)?;
        let cookie = std::str::from_utf8(&bytes)?.trim();
        require(
            cookie.contains(':') && !cookie.contains(['\r', '\n']) && cookie.len() >= 3,
            "invalid RPC cookie",
        )?;
        Ok(format!(
            "Authorization: Basic {}\r\n",
            STANDARD.encode(cookie)
        ))
    }
}

fn body_limits(method: &str, params: &Value) -> (usize, usize) {
    let raw_lookup = matches!(method, "getblock" | "getrawtransaction")
        && params
            .as_array()
            .is_some_and(|p| p.len() == 2 && p[0].is_string() && p[1].as_u64() == Some(0));
    let send = method == "sendrawtransaction"
        && params
            .as_array()
            .is_some_and(|p| p.len() == 1 && p[0].is_string());
    (
        if send { LARGE_HEX_BODY } else { MAX_BODY },
        if raw_lookup { LARGE_HEX_BODY } else { MAX_BODY },
    )
}

impl Rpc for HttpRpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        if self.cookie.is_none() {
            require(
                matches!(
                    method,
                    "getblockchaininfo"
                        | "getblockhash"
                        | "getblock"
                        | "gettxout"
                        | "getrawtransaction"
                        | "sendrawtransaction"
                ),
                "method requires direct authenticated RPC; gateway bootstrap/admin is forbidden",
            )?;
        }
        let (request_limit, response_limit) = body_limits(method, &params);
        let body =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))?;
        require(body.len() <= request_limit, "RPC request too large")?;
        let authentication = self.authentication()?;
        let deadline = Instant::now() + TIMEOUT;
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))?;
        let header = format!("POST / HTTP/1.0\r\nHost: {}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.address, authentication, body.len());
        for part in [header.as_bytes(), body.as_slice()] {
            let mut written = 0;
            while written < part.len() {
                stream.set_write_timeout(Some(
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or("RPC deadline")?,
                ))?;
                let count = stream.write(&part[written..])?;
                require(count > 0, "RPC request write stopped")?;
                written += count;
            }
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
                !name.eq_ignore_ascii_case("transfer-encoding")
                    && !name.eq_ignore_ascii_case("content-encoding"),
                "encoded RPC responses not supported",
            )?;
            if name.eq_ignore_ascii_case("content-length") {
                require(length.is_none(), "duplicate content length")?;
                length = Some(value.trim().parse::<usize>()?);
            }
        }
        let length = length.ok_or("RPC response needs content length")?;
        require(length <= response_limit, "RPC response exceeds bound")?;
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
        let mut response: Value = serde_json::from_slice(&body)?;
        require(
            response["id"] == 1 && response.get("error").is_none_or(Value::is_null),
            "RPC returned error or wrong response id",
        )?;
        response
            .get_mut("result")
            .map(Value::take)
            .ok_or_else(|| "missing RPC result".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_body_classes_do_not_grant_large_verbose_or_unknown_operations() {
        for method in ["getblock", "getrawtransaction"] {
            assert_eq!(
                body_limits(method, &json!(["hash", 0])),
                (2_097_152, 40_100_000)
            );
            for params in [
                json!(["hash", 1]),
                json!(["hash", true]),
                json!([0, 0]),
                json!({"verbosity":0}),
            ] {
                assert_eq!(body_limits(method, &params), (2_097_152, 2_097_152));
            }
        }
        assert_eq!(
            body_limits("sendrawtransaction", &json!(["00"])),
            (40_100_000, 2_097_152)
        );
        for method in ["unknown", "submitblock", "getblockchaininfo"] {
            assert_eq!(
                body_limits(method, &json!(["00", 0])),
                (2_097_152, 2_097_152)
            );
        }
    }
}
