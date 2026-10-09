//! Bounded connection to an operator-trusted local Zakura RPC.
//! Numeric loopback endpoints only; remote nodes require a trusted local tunnel.
//! HTTP/1.0 close framing avoids adding an HTTP/TLS/authentication stack to the
//! prototype. Unsupported HTTP framing fails; it never falls back to an index.
use crate::{manifest::decode_hex, ChainSource, Checkpoint, Error, Hex, NodeContext};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

const MAX_RESPONSE: usize = 4_100_000;
const MAX_HEADER: usize = 16_384;

/// Bounded transport to an independently authenticated numeric loopback node.
pub struct LocalRpc {
    address: SocketAddr,
}
impl LocalRpc {
    /// Reject remote, unspecified, DNS and zero-port endpoints.
    pub fn new(address: SocketAddr) -> Result<Self, Error> {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(Error::UnsupportedContext);
        }
        Ok(Self { address })
    }
    fn call(&self, method: &str, params: Value) -> Result<Value, Error> {
        let value = self.call_nullable(method, params, false)?;
        if value.is_null() {
            return Err(Error::HistoryUnavailable);
        }
        Ok(value)
    }
    fn call_nullable(
        &self,
        method: &str,
        params: Value,
        missing_transaction: bool,
    ) -> Result<Value, Error> {
        let body =
            serde_json::to_vec(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
                .map_err(|_| Error::Encoding)?;
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(5))
            .map_err(|_| Error::HistoryUnavailable)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|_| Error::HistoryUnavailable)?;
        write!(stream, "POST / HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.address, body.len()).map_err(|_| Error::HistoryUnavailable)?;
        stream
            .write_all(&body)
            .map_err(|_| Error::HistoryUnavailable)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut response = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Error::HistoryUnavailable)?;
            stream
                .set_read_timeout(Some(remaining))
                .map_err(|_| Error::HistoryUnavailable)?;
            let count = stream
                .read(&mut buffer)
                .map_err(|_| Error::HistoryUnavailable)?;
            if count == 0 {
                break;
            }
            if response.len() + count > MAX_RESPONSE + MAX_HEADER {
                return Err(Error::Limits);
            }
            response.extend_from_slice(&buffer[..count]);
        }
        parse_response_kind(&response, missing_transaction)
    }
}

#[cfg(test)]
fn parse_response(response: &[u8]) -> Result<Value, Error> {
    let value = parse_response_kind(response, false)?;
    if value.is_null() {
        return Err(Error::HistoryUnavailable);
    }
    Ok(value)
}
fn parse_response_kind(response: &[u8], missing_transaction: bool) -> Result<Value, Error> {
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(Error::HistoryUnavailable)?;
    if end > MAX_HEADER || response.len() - end - 4 > MAX_RESPONSE {
        return Err(Error::Limits);
    }
    let header = std::str::from_utf8(&response[..end]).map_err(|_| Error::HistoryUnavailable)?;
    let mut lines = header.split("\r\n");
    let mut status = lines
        .next()
        .ok_or(Error::HistoryUnavailable)?
        .split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) || status.next() != Some("200") {
        return Err(Error::HistoryUnavailable);
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Error::HistoryUnavailable)?;
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-encoding")
        {
            return Err(Error::HistoryUnavailable);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(Error::HistoryUnavailable);
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| Error::HistoryUnavailable)?,
            );
        }
    }
    let body = &response[end + 4..];
    if length.is_some_and(|n| n != body.len()) {
        return Err(Error::HistoryUnavailable);
    }
    let envelope: Value = serde_json::from_slice(body).map_err(|_| Error::HistoryUnavailable)?;
    if envelope.get("id") != Some(&json!(1)) {
        return Err(Error::HistoryUnavailable);
    }
    if let Some(error) = envelope.get("error").filter(|e| !e.is_null()) {
        if missing_transaction
            && error.get("code").and_then(Value::as_i64) == Some(-5)
            && envelope.get("result").is_none_or(Value::is_null)
        {
            return Ok(Value::Null);
        }
        return Err(Error::HistoryUnavailable);
    }
    envelope
        .get("result")
        .cloned()
        .ok_or(Error::HistoryUnavailable)
}

fn number(value: &Value) -> Result<u32, Error> {
    value
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(Error::HistoryUnavailable)
}
fn bytes<const N: usize>(value: &Value) -> Result<Hex<N>, Error> {
    let mut result = [0; N];
    decode_hex(
        value.as_str().ok_or(Error::HistoryUnavailable)?,
        &mut result,
    )
    .map_err(|_| Error::HistoryUnavailable)?;
    Ok(Hex(result))
}
impl ChainSource for LocalRpc {
    fn context(&mut self) -> Result<NodeContext, Error> {
        let value = self.call("getblockchaininfo", json!([]))?;
        Ok(NodeContext {
            chain: value["chain"]
                .as_str()
                .ok_or(Error::HistoryUnavailable)?
                .into(),
            next_branch_id: bytes(&value["consensus"]["nextblock"])?,
            nu7_activation_height: number(&value["upgrades"]["77190ad9"]["activationheight"])?,
            tip: Checkpoint {
                hash: bytes(&value["bestblockhash"])?,
                height: number(&value["blocks"])?,
            },
        })
    }
    fn block_hash(&mut self, height: u32) -> Result<Hex<32>, Error> {
        bytes(&self.call("getblockhash", json!([height]))?)
    }
    fn block_bytes(&mut self, hash: Hex<32>) -> Result<Vec<u8>, Error> {
        let value = self.call("getblock", json!([hex::encode(hash.0), 0]))?;
        let text = value.as_str().ok_or(Error::HistoryUnavailable)?;
        if text.len() as u64 > 2 * zakura_chain::block::MAX_BLOCK_BYTES {
            return Err(Error::Limits);
        }
        hex::decode(text).map_err(|_| Error::HistoryUnavailable)
    }
}

impl LocalRpc {
    fn confirmed_block(&mut self, height: u32) -> Result<zakura_chain::block::Block, Error> {
        use zakura_chain::{
            block::{merkle, Block},
            serialization::{BytesInDisplayOrder, ZcashDeserialize},
        };
        let hash = self.block_hash(height)?;
        let raw = self.block_bytes(hash)?;
        let mut reader = std::io::Cursor::new(&raw);
        let block = Block::zcash_deserialize(&mut reader).map_err(|_| Error::HistoryUnavailable)?;
        if reader.position() != raw.len() as u64
            || Hex(block.hash().bytes_in_display_order()) != hash
            || block.coinbase_height().map(|h| h.0) != Some(height)
            || block
                .transactions
                .iter()
                .map(|t| t.hash())
                .collect::<merkle::Root>()
                != block.header.merkle_root
        {
            return Err(Error::ChainChanged);
        }
        Ok(block)
    }
}
impl crate::payment::PaymentSource for LocalRpc {
    fn resolve(
        &mut self,
        point: crate::Outpoint,
    ) -> Result<Option<crate::payment::ResolvedInput>, Error> {
        use zakura_chain::serialization::BytesInDisplayOrder;
        let context = self.context()?;
        let value = self.call_nullable(
            "gettxout",
            json!([hex::encode(point.txid.0), point.index, true]),
            false,
        )?;
        if value.is_null() {
            return Ok(None);
        }
        let confirmations = number(&value["confirmations"])?;
        if confirmations == 0 {
            return Ok(None);
        }
        if bytes::<32>(&value["bestblock"])? != context.tip.hash {
            return Err(Error::ChainChanged);
        }
        let height = context
            .tip
            .height
            .checked_add(1)
            .and_then(|h| h.checked_sub(confirmations))
            .ok_or(Error::ChainChanged)?;
        let block = self.confirmed_block(height)?;
        let tx = block
            .transactions
            .iter()
            .find(|t| Hex(t.hash().bytes_in_display_order()) == point.txid)
            .ok_or(Error::InputContext)?;
        let output = tx
            .outputs()
            .get(point.index as usize)
            .ok_or(Error::InputContext)?
            .clone();
        if value["coinbase"].as_bool() != Some(tx.is_coinbase())
            || value["scriptPubKey"]["hex"].as_str()
                != Some(hex::encode(output.lock_script.as_raw_bytes()).as_str())
        {
            return Err(Error::InputContext);
        }
        // gettxout exposes a lossy floating-point ZEC value. Use the exact amount
        // in the confirmed block instead, with gettxout establishing unspentness.
        Ok(Some(crate::payment::ResolvedInput {
            output,
            height,
            coinbase: tx.is_coinbase(),
            tip: context.tip,
        }))
    }
    fn transaction(
        &mut self,
        txid: Hex<32>,
    ) -> Result<Option<crate::payment::LocatedTransaction>, Error> {
        use zakura_chain::{
            serialization::{BytesInDisplayOrder, ZcashDeserialize},
            transaction::Transaction,
        };
        let value =
            self.call_nullable("getrawtransaction", json!([hex::encode(txid.0), 1]), true)?;
        if value.is_null() {
            return Ok(None);
        }
        let text = value["hex"].as_str().ok_or(Error::HistoryUnavailable)?;
        if text.len() > 2 * crate::payment::MAX_TRANSACTION {
            return Err(Error::Limits);
        }
        let raw = hex::decode(text).map_err(|_| Error::HistoryUnavailable)?;
        let mut reader = std::io::Cursor::new(&raw);
        let tx =
            Transaction::zcash_deserialize(&mut reader).map_err(|_| Error::HistoryUnavailable)?;
        if reader.position() != raw.len() as u64 || Hex(tx.hash().bytes_in_display_order()) != txid
        {
            return Err(Error::InputContext);
        }
        let block = if let Some(height) = value.get("height").filter(|v| !v.is_null()) {
            if height.as_i64() == Some(-1) {
                return Ok(None);
            }
            let height = number(height)?;
            let block = self.confirmed_block(height)?;
            if !block.transactions.iter().any(|t| t.hash() == tx.hash()) {
                return Err(Error::ChainChanged);
            }
            Some(Checkpoint {
                height,
                hash: Hex(block.hash().bytes_in_display_order()),
            })
        } else {
            if value
                .get("confirmations")
                .is_some_and(|c| !c.is_null() && c.as_u64() != Some(0))
            {
                return Err(Error::HistoryUnavailable);
            }
            None
        };
        Ok(Some(crate::payment::LocatedTransaction {
            bytes: raw,
            block,
        }))
    }
    fn submit(&mut self, transaction: &[u8]) -> Result<Hex<32>, Error> {
        if transaction.len() > crate::payment::MAX_TRANSACTION {
            return Err(Error::Limits);
        }
        bytes(&self.call("sendrawtransaction", json!([hex::encode(transaction)]))?)
    }
}

#[cfg(test)]
mod tests {
    mod payment;
    use super::*;
    #[test]
    fn nullable_rpc_results_do_not_hide_transport_or_server_failures() {
        let response = |body: Value| {
            [
                b"HTTP/1.0 200 OK\r\n\r\n".to_vec(),
                serde_json::to_vec(&body).unwrap(),
            ]
            .concat()
        };
        assert!(
            parse_response_kind(&response(json!({"id":1,"result":null})), false)
                .unwrap()
                .is_null()
        );
        let missing = response(json!({"id":1,"result":null,"error":{"code":-5}}));
        assert!(parse_response_kind(&missing, true).unwrap().is_null());
        assert!(parse_response_kind(&missing, false).is_err());
        for body in [
            json!({"id":1}),
            json!({"id":1,"error":{"code":-1}}),
            json!({"id":2,"error":{"code":-5}}),
            json!({"id":1,"result":{},"error":{"code":-5}}),
        ] {
            assert!(parse_response_kind(&response(body), true).is_err());
        }
        assert!(parse_response_kind(
            b"HTTP/1.0 500 Error\r\n\r\n{\"id\":1,\"error\":{\"code\":-5}}",
            true
        )
        .is_err());
    }
    #[test]
    fn http_errors_and_unavailable_history_are_never_empty_results() {
        let valid = br#"{"jsonrpc":"2.0","id":1,"result":"abc"}"#;
        let response = |header: &str, body: &[u8]| [header.as_bytes(), b"\r\n\r\n", body].concat();
        assert_eq!(
            parse_response(&response("HTTP/1.0 200 OK", valid)).unwrap(),
            "abc"
        );
        for (header, body) in [
            ("HTTP/1.1 500 Error", &valid[..]),
            ("HTTP/1.1 200 OK\r\nContent-Length: 1", &valid[..]),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked", &valid[..]),
            ("HTTP/1.1 200 OK", &br#"{"id":2,"result":"abc"}"#[..]),
            (
                "HTTP/1.1 200 OK",
                &br#"{"id":1,"result":null,"error":{"code":-5}}"#[..],
            ),
        ] {
            assert!(matches!(
                parse_response(&response(header, body)),
                Err(Error::HistoryUnavailable)
            ));
        }
        assert!(LocalRpc::new("192.0.2.1:8232".parse().unwrap()).is_err());
    }
}
