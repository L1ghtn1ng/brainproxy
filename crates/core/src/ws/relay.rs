//! Relays an upgraded WebSocket connection between a client and a server, one task per
//! direction. Frames are parsed as they pass and forwarded byte for byte; every message is
//! handed to [`Hooks::record`]. A data message is forwarded once its last fragment arrives
//! (control frames at once), so it can be held for an intercept decision first.
//!
//! An edited message goes out as one uncompressed frame (permessage-deflate lets any message
//! be sent uncompressed). When the sender keeps its compression window between messages,
//! its later messages may refer back to the one that was replaced or dropped, which the
//! receiver never saw: from then on that direction's compressed messages are sent
//! decompressed too. A frame the parser refuses (or one over [`MAX_MESSAGE`]) ends
//! recording for that direction; its bytes and everything after are relayed unchanged.

use std::future::Future;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::ws::{
    encode_frame, parse_frame, random_mask, Assembler, Deflate, Direction, Message, MAX_MESSAGE, OP_CLOSE, OP_PING,
    OP_PONG,
};

/// How long the other direction may go on once one side has closed its connection.
const LINGER: Duration = Duration::from_secs(10);

/// Frame headers a message may add on top of its payload before it counts as too large
/// (a peer could otherwise send endless empty continuation frames).
const MAX_FRAMING: usize = 1024 * 1024;

/// What happens to a held message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hold {
    Forward,
    /// Forward this payload instead (same opcode).
    Edited(Vec<u8>),
    Drop,
}

pub trait Hooks: Sync {
    /// A message passed (or was dropped: `intercept` says so).
    fn record(&self, direction: Direction, message: &Message, intercept: Option<&'static str>);
    /// Whether the next complete data message going this way is held.
    fn should_hold(&self, direction: Direction) -> bool;
    /// Holds a data message until someone decides.
    fn hold(&self, direction: Direction, message: &Message) -> impl Future<Output = Hold> + Send;
}

/// How a relayed connection ended.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ended {
    /// Code and reason of the first close frame, from either side.
    pub close_code: Option<u16>,
    pub close_reason: Option<String>,
    /// Why recording stopped early, if it did.
    pub error: Option<String>,
}

#[derive(Default)]
struct PumpEnd {
    /// (time, code, reason) of the first close frame this way.
    close: Option<(String, Option<u16>, Option<String>)>,
    error: Option<String>,
}

/// Relays until both sides are done (or one is and the other stays quiet for a while).
/// `from_client` and `from_server` are bytes each side sent that were already read.
pub async fn relay<C, S, H>(
    client: C,
    from_client: Vec<u8>,
    server: S,
    from_server: Vec<u8>,
    deflate: Deflate,
    hooks: &H,
) -> Ended
where
    C: AsyncRead + AsyncWrite,
    S: AsyncRead + AsyncWrite,
    H: Hooks,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (server_read, server_write) = tokio::io::split(server);
    let up = pump(client_read, server_write, from_client, Direction::ToServer, deflate, hooks);
    let down = pump(server_read, client_write, from_server, Direction::ToClient, deflate, hooks);
    tokio::pin!(up, down);
    let (up, down) = tokio::select! {
        u = &mut up => (Some(u), tokio::time::timeout(LINGER, &mut down).await.ok()),
        d = &mut down => (tokio::time::timeout(LINGER, &mut up).await.ok(), Some(d)),
    };
    let (up, down) = (up.unwrap_or_default(), down.unwrap_or_default());
    let close = match (up.close, down.close) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    };
    let (close_code, close_reason) = close.map(|(_, c, r)| (c, r)).unwrap_or_default();
    Ended { close_code, close_reason, error: up.error.or(down.error) }
}

async fn pump<R, W, H>(from: R, mut to: W, buf: Vec<u8>, dir: Direction, deflate: Deflate, hooks: &H) -> PumpEnd
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Hooks,
{
    let mut end = PumpEnd::default();
    let _ = pump_inner(from, &mut to, buf, dir, deflate, hooks, &mut end).await;
    let _ = to.shutdown().await;
    end
}

async fn pump_inner<R, W, H>(
    mut from: R,
    to: &mut W,
    mut buf: Vec<u8>,
    dir: Direction,
    deflate: Deflate,
    hooks: &H,
    end: &mut PumpEnd,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Hooks,
{
    let mut assembler = Assembler::new(deflate, dir, MAX_MESSAGE);
    let takeover = deflate.takeover(dir);
    let allowed_rsv = if deflate.enabled { 0x4 } else { 0 };
    let mask = || (dir == Direction::ToServer).then(random_mask);
    // Raw frames of the data message being reassembled, not yet forwarded.
    let mut pending: Vec<u8> = Vec::new();
    // Messages this way can no longer be forwarded compressed (see the module docs).
    let mut diverged = false;
    let mut chunk = vec![0u8; 64 * 1024];
    // The sender closed its side (seen while a message was held).
    let mut eof = false;
    loop {
        let mut used = 0;
        while end.error.is_none() {
            // RSV bits no extension asked for: not WebSocket framing, so don't wait for the
            // rest of a "frame" that may never come.
            if buf.get(used).is_some_and(|b| (b >> 4) & 0x7 & !allowed_rsv != 0) {
                end.error = Some(format!("{}: WebSocket frame with RSV bits no extension negotiated", dir.as_str()));
                break;
            }
            let (frame, n) = match parse_frame(&buf[used..], MAX_MESSAGE) {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    end.error = Some(format!("{}: {e}", dir.as_str()));
                    break;
                }
            };
            let raw = &buf[used..used + n];
            used += n;
            let complete = match assembler.push(&frame) {
                Ok(m) => m,
                Err(e) => {
                    pending.extend_from_slice(raw);
                    end.error = Some(format!("{}: {e}", dir.as_str()));
                    break;
                }
            };
            if frame.is_control() {
                let Some(m) = complete else { continue };
                hooks.record(dir, &m, None);
                if m.opcode == OP_CLOSE && end.close.is_none() {
                    let (code, reason) = m.close_info();
                    end.close = Some((m.time.clone(), code, reason));
                }
                to.write_all(raw).await?;
                continue;
            }
            pending.extend_from_slice(raw);
            if pending.len() > MAX_MESSAGE + MAX_FRAMING {
                end.error = Some(format!("{}: WebSocket message in too many frames", dir.as_str()));
                break;
            }
            let Some(m) = complete else { continue };
            let decision = if hooks.should_hold(dir) {
                to.flush().await?;
                let decided = hooks.hold(dir, &m);
                tokio::pin!(decided);
                // Pings and pongs keep flowing while the message waits, so heartbeats don't time
                // out. Anything else (data, close) waits behind the held message.
                loop {
                    while let Ok(Some((f, n))) = parse_frame(&buf[used..], MAX_MESSAGE) {
                        if !matches!(f.opcode, OP_PING | OP_PONG) || f.rsv != 0 {
                            break;
                        }
                        hooks.record(dir, &Message::new(f.opcode, f.payload), None);
                        to.write_all(&buf[used..used + n]).await?;
                        used += n;
                    }
                    to.flush().await?;
                    if eof {
                        break decided.await;
                    }
                    tokio::select! {
                        d = &mut decided => break d,
                        read = from.read(&mut chunk) => match read? {
                            0 => eof = true,
                            n => buf.extend_from_slice(&chunk[..n]),
                        },
                    }
                }
            } else {
                Hold::Forward
            };
            match decision {
                Hold::Forward => {
                    hooks.record(dir, &m, None);
                    if diverged && m.compressed {
                        to.write_all(&encode_frame(true, 0, m.opcode, &m.payload, mask())).await?;
                    } else {
                        to.write_all(&pending).await?;
                    }
                }
                Hold::Edited(payload) => {
                    let edited = Message { payload, compressed: false, fragments: 1, ..m.clone() };
                    hooks.record(dir, &edited, Some("edited"));
                    to.write_all(&encode_frame(true, 0, m.opcode, &edited.payload, mask())).await?;
                    diverged |= m.compressed && takeover;
                }
                Hold::Drop => {
                    hooks.record(dir, &m, Some("dropped"));
                    diverged |= m.compressed && takeover;
                }
            }
            pending.clear();
        }
        if end.error.is_some() {
            // Not a frame we can follow: relay the rest unchanged, unrecorded.
            to.write_all(&pending).await?;
            to.write_all(&buf[used..]).await?;
            tokio::io::copy(&mut from, to).await?;
            return Ok(());
        }
        buf.drain(..used);
        to.flush().await?;
        let n = if eof { 0 } else { from.read(&mut chunk).await? };
        if n == 0 {
            // Whatever was left unfinished still belongs to the other side.
            to.write_all(&pending).await?;
            to.write_all(&buf).await?;
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{close_payload, OP_BINARY, OP_TEXT};
    use std::sync::Mutex;
    use tokio::io::duplex;

    /// A recorded message: direction, opcode, payload, and why it was marked.
    type Seen = (Direction, u8, Vec<u8>, Option<&'static str>);

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Seen>>,
        hold_to_server: bool,
        decision: Mutex<Vec<Hold>>,
        hold_for: Duration,
    }

    impl Hooks for Recorder {
        fn record(&self, d: Direction, m: &Message, i: Option<&'static str>) {
            self.seen.lock().unwrap().push((d, m.opcode, m.payload.clone(), i));
        }
        fn should_hold(&self, d: Direction) -> bool {
            self.hold_to_server && d == Direction::ToServer
        }
        fn hold(&self, _: Direction, _: &Message) -> impl Future<Output = Hold> + Send {
            let d = self.decision.lock().unwrap().remove(0);
            let wait = self.hold_for;
            async move {
                tokio::time::sleep(wait).await;
                d
            }
        }
    }

    /// Reads what one end received until it closes, parsing frames.
    async fn frames_from<R: AsyncRead + Unpin>(mut r: R) -> (Vec<u8>, Vec<(u8, u8, Vec<u8>)>) {
        let mut all = Vec::new();
        r.read_to_end(&mut all).await.unwrap();
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some((f, n)) = parse_frame(&all[pos..], MAX_MESSAGE).unwrap() {
            out.push((f.opcode, f.rsv, f.payload));
            pos += n;
        }
        (all, out)
    }

    #[tokio::test]
    async fn relays_bytes_unchanged_and_records_both_ways() {
        let (client, proxy_client) = duplex(1 << 20);
        let (proxy_server, server) = duplex(1 << 20);
        let rec = Recorder::default();
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut server_r, mut server_w) = tokio::io::split(server);
        // The first frame was read with the upgrade request already.
        let early = encode_frame(true, 0, OP_TEXT, b"early", Some([9, 9, 9, 9]));
        let mut to_server = encode_frame(false, 0, OP_TEXT, b"frag", Some([1, 2, 3, 4]));
        to_server.extend(encode_frame(true, 0, OP_PING, b"p", Some([5, 6, 7, 8])));
        to_server.extend(encode_frame(true, 0, 0, b"mented", Some([1, 1, 1, 1])));
        to_server.extend(encode_frame(true, 0, OP_CLOSE, &close_payload(1000, "done"), Some([2, 2, 2, 2])));
        let to_client = encode_frame(true, 0, OP_BINARY, &[0, 159, 146, 150], None);
        let (tc, ts) = (to_client.clone(), to_server.clone());
        let ended = tokio::join!(
            relay(proxy_client, early.clone(), proxy_server, Vec::new(), Deflate::default(), &rec),
            async move {
                // Byte by byte, to cross every frame boundary.
                for b in &ts {
                    client_w.write_all(&[*b]).await.unwrap();
                }
                client_w.shutdown().await.unwrap();
            },
            async move {
                server_w.write_all(&tc).await.unwrap();
                server_w.shutdown().await.unwrap();
            },
            async move {
                let mut got = Vec::new();
                server_r.read_to_end(&mut got).await.unwrap();
                // The ping overtakes the fragmented message it arrived in the middle of.
                let mut want = early.clone();
                want.extend(encode_frame(true, 0, OP_PING, b"p", Some([5, 6, 7, 8])));
                want.extend(encode_frame(false, 0, OP_TEXT, b"frag", Some([1, 2, 3, 4])));
                want.extend(encode_frame(true, 0, 0, b"mented", Some([1, 1, 1, 1])));
                want.extend(encode_frame(true, 0, OP_CLOSE, &close_payload(1000, "done"), Some([2, 2, 2, 2])));
                assert_eq!(got, want);
            },
            async move {
                let mut got = Vec::new();
                client_r.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, to_client);
            },
        )
        .0;
        assert_eq!((ended.close_code, ended.close_reason.as_deref(), ended.error), (Some(1000), Some("done"), None));
        let seen = rec.seen.lock().unwrap();
        let mut ups: Vec<_> = seen.iter().filter(|s| s.0 == Direction::ToServer).map(|s| (s.1, s.2.clone())).collect();
        ups.sort();
        assert_eq!(
            ups,
            vec![
                (OP_TEXT, b"early".to_vec()),
                (OP_TEXT, b"fragmented".to_vec()),
                (OP_CLOSE, close_payload(1000, "done")),
                (OP_PING, b"p".to_vec())
            ]
        );
        assert!(seen.iter().any(|s| s.0 == Direction::ToClient && s.2 == [0, 159, 146, 150]));
    }

    #[tokio::test]
    async fn held_messages_are_edited_or_dropped() {
        use flate2::{Compress, Compression, FlushCompress};
        let deflate = Deflate { enabled: true, ..Default::default() };
        let mut c = Compress::new(Compression::default(), false);
        let mut compressed = |data: &[u8]| {
            let mut out = Vec::with_capacity(data.len() + 64);
            c.compress_vec(data, &mut out, FlushCompress::Sync).unwrap();
            out.truncate(out.len() - 4);
            out
        };
        let (client, proxy_client) = duplex(1 << 20);
        let (proxy_server, server) = duplex(1 << 20);
        let rec = Recorder {
            hold_to_server: true,
            decision: Mutex::new(vec![Hold::Edited(b"changed".to_vec()), Hold::Drop, Hold::Forward]),
            ..Default::default()
        };
        // Three compressed messages from the client; with context takeover the later ones may
        // refer back to the edited and dropped ones.
        let mut sent = Vec::new();
        for m in [&b"original original"[..], b"original dropped", b"original kept"] {
            sent.extend(encode_frame(true, 4, OP_TEXT, &compressed(m), Some(random_mask())));
        }
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (server_r, mut server_w) = tokio::io::split(server);
        let (_, (_, frames), _, _) = tokio::join!(
            relay(proxy_client, Vec::new(), proxy_server, Vec::new(), deflate, &rec),
            frames_from(server_r),
            async move {
                client_w.write_all(&sent).await.unwrap();
                client_w.shutdown().await.unwrap();
            },
            async move {
                server_w.shutdown().await.unwrap();
                let mut sink = Vec::new();
                client_r.read_to_end(&mut sink).await.unwrap();
            },
        );
        // The edited message and the one after it arrive uncompressed (RSV1 clear).
        assert_eq!(frames, vec![(OP_TEXT, 0, b"changed".to_vec()), (OP_TEXT, 0, b"original kept".to_vec())]);
        let seen = rec.seen.lock().unwrap();
        let marks: Vec<_> = seen.iter().map(|s| (s.2.clone(), s.3)).collect();
        assert_eq!(
            marks,
            vec![
                (b"changed".to_vec(), Some("edited")),
                (b"original dropped".to_vec(), Some("dropped")),
                (b"original kept".to_vec(), None)
            ]
        );
    }

    #[tokio::test]
    async fn unparseable_traffic_is_relayed_unchanged() {
        let (client, proxy_client) = duplex(1 << 20);
        let (proxy_server, server) = duplex(1 << 20);
        let rec = Recorder::default();
        let mut junk = encode_frame(true, 0, OP_TEXT, b"ok", Some([1, 2, 3, 4]));
        junk.extend_from_slice(&[0x83, 0x00, 1, 2, 3, 4, 5]);
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut server_r, mut server_w) = tokio::io::split(server);
        let want = junk.clone();
        let (ended, ..) = tokio::join!(
            relay(proxy_client, Vec::new(), proxy_server, Vec::new(), Deflate::default(), &rec),
            async move {
                client_w.write_all(&junk).await.unwrap();
                client_w.shutdown().await.unwrap();
            },
            async move {
                let mut got = Vec::new();
                server_r.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, want);
                server_w.shutdown().await.unwrap();
            },
            async move {
                let mut sink = Vec::new();
                client_r.read_to_end(&mut sink).await.unwrap();
            },
        );
        assert!(ended.error.unwrap().contains("reserved opcode"));
        assert_eq!(rec.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn pings_pass_while_a_message_is_held() {
        let (client, proxy_client) = duplex(1 << 20);
        let (proxy_server, server) = duplex(1 << 20);
        let rec = Recorder {
            hold_to_server: true,
            decision: Mutex::new(vec![Hold::Forward]),
            hold_for: Duration::from_millis(300),
            ..Default::default()
        };
        let mut sent = encode_frame(true, 0, OP_TEXT, b"held", Some([1, 2, 3, 4]));
        sent.extend(encode_frame(true, 0, OP_PING, b"beat", Some([5, 6, 7, 8])));
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (server_r, mut server_w) = tokio::io::split(server);
        let (_, (_, frames), _, _) = tokio::join!(
            relay(proxy_client, Vec::new(), proxy_server, Vec::new(), Deflate::default(), &rec),
            frames_from(server_r),
            async move {
                client_w.write_all(&sent).await.unwrap();
                tokio::time::sleep(Duration::from_millis(500)).await;
                client_w.shutdown().await.unwrap();
            },
            async move {
                server_w.shutdown().await.unwrap();
                let mut sink = Vec::new();
                client_r.read_to_end(&mut sink).await.unwrap();
            },
        );
        assert_eq!(frames, vec![(OP_PING, 0, b"beat".to_vec()), (OP_TEXT, 0, b"held".to_vec())]);
    }

    #[tokio::test]
    async fn endless_empty_fragments_stop_recording() {
        let (client, proxy_client) = duplex(1 << 20);
        let (proxy_server, server) = duplex(1 << 20);
        let rec = Recorder::default();
        let (mut client_r, mut client_w) = tokio::io::split(client);
        let (mut server_r, mut server_w) = tokio::io::split(server);
        let (ended, ..) = tokio::join!(
            relay(proxy_client, Vec::new(), proxy_server, Vec::new(), Deflate::default(), &rec),
            async move {
                client_w.write_all(&encode_frame(false, 0, OP_TEXT, b"", None)).await.unwrap();
                let empty = encode_frame(false, 0, 0, b"", None).repeat(64 * 1024);
                // Far more framing than any message may carry; the relay must not keep it all.
                for _ in 0..((MAX_MESSAGE + MAX_FRAMING) / empty.len() + 2) {
                    client_w.write_all(&empty).await.unwrap();
                }
                client_w.shutdown().await.unwrap();
            },
            async move {
                let mut got = 0usize;
                let mut chunk = vec![0u8; 1 << 16];
                loop {
                    match server_r.read(&mut chunk).await.unwrap() {
                        0 => break,
                        n => got += n,
                    }
                }
                assert!(got > MAX_MESSAGE, "everything is still relayed: {got}");
                server_w.shutdown().await.unwrap();
            },
            async move {
                let mut sink = Vec::new();
                client_r.read_to_end(&mut sink).await.unwrap();
            },
        );
        assert!(ended.error.unwrap().contains("too many frames"));
    }
}
