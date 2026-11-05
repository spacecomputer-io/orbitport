//! Local stdio adapter. The gateway remains the authentication and KMS boundary.
pub mod client;
pub mod types;

use kms_mcp_core::{Dispatch, ToolPolicy, dispatch, protocol_error};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_MESSAGE_BYTES: usize = 65_536;

// Read with fill_buf rather than read_line so an untrusted oversized line
// cannot grow an unbounded allocation before its length is checked.
async fn read_message<R: AsyncBufRead + Unpin>(input: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = input.fill_buf().await?;
        if buf.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let count = buf
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buf.len(), |n| n + 1);
        if line.len() + count > MAX_MESSAGE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "MCP message exceeds size limit",
            ));
        }
        let ended = buf[count - 1] == b'\n';
        line.extend_from_slice(&buf[..count]);
        input.consume(count);
        if ended {
            return Ok(Some(line));
        }
    }
}

pub async fn serve<R, W>(
    mut input: R,
    mut output: W,
    client: client::GatewayClient,
    policy: ToolPolicy,
) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    while let Some(line) = read_message(&mut input).await? {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let response = match std::str::from_utf8(&line) {
            Err(_) => protocol_error(None, -32700, "Parse error"),
            Ok(line) => match dispatch(line, &policy) {
                Dispatch::Reply(reply) => reply,
                Dispatch::Notification => continue,
                Dispatch::Call(pending) => match client.execute(&pending.call).await {
                    Ok(result) => pending.success(result),
                    Err(error) => pending.failure(error.to_string()),
                },
            },
        };
        output.write_all(response.as_bytes()).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
    }
    Ok(())
}
