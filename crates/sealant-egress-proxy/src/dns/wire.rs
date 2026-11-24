//! The DNS message format (RFC 1035), as much as the validating server needs.
//!
//! Parsing is defensive: every length is bounds-checked, compression pointers may only point
//! backwards and are followed a bounded number of times. Responses the proxy builds never use
//! compression, so a record copied from upstream cannot carry a pointer into bytes that are gone.

use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const TYPE_A: u16 = 1;
pub(crate) const TYPE_NS: u16 = 2;
pub(crate) const TYPE_CNAME: u16 = 5;
pub(crate) const TYPE_PTR: u16 = 12;
pub(crate) const TYPE_MX: u16 = 15;
pub(crate) const TYPE_TXT: u16 = 16;
pub(crate) const TYPE_AAAA: u16 = 28;
pub(crate) const TYPE_SRV: u16 = 33;
pub(crate) const TYPE_OPT: u16 = 41;
pub(crate) const TYPE_SVCB: u16 = 64;
pub(crate) const TYPE_HTTPS: u16 = 65;
pub(crate) const CLASS_IN: u16 = 1;

pub(crate) const RCODE_NOERROR: u8 = 0;
pub(crate) const RCODE_FORMERR: u8 = 1;
pub(crate) const RCODE_SERVFAIL: u8 = 2;
pub(crate) const RCODE_NXDOMAIN: u8 = 3;
pub(crate) const RCODE_NOTIMP: u8 = 4;
pub(crate) const RCODE_REFUSED: u8 = 5;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed DNS message: {0}")]
pub(crate) struct WireError(pub(crate) &'static str);

/// A domain name as its wire labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Name(pub(crate) Vec<Vec<u8>>);

impl Name {
    /// The lowercased dotted form, when every label is a plain hostname label.
    pub(crate) fn hostname(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (i, label) in self.0.iter().enumerate() {
            if !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return None;
            }
            if i > 0 {
                out.push('.');
            }
            out.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
        }
        Some(out)
    }

    pub(crate) fn from_hostname(host: &str) -> Result<Self, WireError> {
        let labels: Vec<Vec<u8>> = host
            .trim_end_matches('.')
            .split('.')
            .map(|l| l.as_bytes().to_vec())
            .collect();
        if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
            return Err(WireError("bad label"));
        }
        let name = Self(labels);
        if name.wire_len() > 255 {
            return Err(WireError("name too long"));
        }
        Ok(name)
    }

    fn wire_len(&self) -> usize {
        self.0.iter().map(|l| l.len() + 1).sum::<usize>() + 1
    }

    fn encode(&self, out: &mut Vec<u8>) {
        for label in &self.0 {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub(crate) name: Name,
    pub(crate) qtype: u16,
    pub(crate) qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// CNAME, NS, PTR.
    Name(Name),
    Mx(u16, Name),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    /// TXT and other types whose RDATA carries no names.
    Raw(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) name: Name,
    pub(crate) rtype: u16,
    pub(crate) class: u16,
    pub(crate) ttl: u32,
    pub(crate) data: RData,
}

#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) id: u16,
    pub(crate) flags: u16,
    pub(crate) questions: Vec<Question>,
    pub(crate) answers: Vec<Record>,
    /// The requester's EDNS UDP payload size, from an OPT record in the additional section.
    pub(crate) edns_udp_size: Option<u16>,
}

impl Message {
    pub(crate) fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0x0f) as u8
    }
    pub(crate) fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
    pub(crate) fn truncated(&self) -> bool {
        self.flags & 0x0200 != 0
    }
    pub(crate) fn rcode(&self) -> u8 {
        (self.flags & 0x000f) as u8
    }
    pub(crate) fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError("overflow"))?;
        let bytes = self.buf.get(self.pos..end).ok_or(WireError("truncated"))?;
        self.pos = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn name(&mut self) -> Result<Name, WireError> {
        let mut labels = Vec::new();
        let mut total = 1usize;
        let mut pos = self.pos;
        let mut jumped = false;
        let mut jumps = 0;
        loop {
            let len = *self.buf.get(pos).ok_or(WireError("truncated name"))?;
            match len & 0xc0 {
                0x00 => {
                    if len == 0 {
                        pos += 1;
                        break;
                    }
                    let start = pos + 1;
                    let end = start + usize::from(len);
                    let label = self
                        .buf
                        .get(start..end)
                        .ok_or(WireError("truncated label"))?;
                    total += label.len() + 1;
                    if total > 255 {
                        return Err(WireError("name too long"));
                    }
                    labels.push(label.to_vec());
                    pos = end;
                }
                0xc0 => {
                    let low = *self
                        .buf
                        .get(pos + 1)
                        .ok_or(WireError("truncated pointer"))?;
                    let target = (usize::from(len & 0x3f) << 8) | usize::from(low);
                    if target >= pos {
                        return Err(WireError("forward compression pointer"));
                    }
                    jumps += 1;
                    if jumps > 32 {
                        return Err(WireError("compression loop"));
                    }
                    if !jumped {
                        self.pos = pos + 2;
                        jumped = true;
                    }
                    pos = target;
                }
                _ => return Err(WireError("reserved label type")),
            }
        }
        if !jumped {
            self.pos = pos;
        }
        Ok(Name(labels))
    }

    fn question(&mut self) -> Result<Question, WireError> {
        Ok(Question {
            name: self.name()?,
            qtype: self.u16()?,
            qclass: self.u16()?,
        })
    }

    /// One resource record. OPT records come back as `Raw` with the UDP size as their class.
    fn record(&mut self) -> Result<Record, WireError> {
        let name = self.name()?;
        let rtype = self.u16()?;
        let class = self.u16()?;
        let ttl = self.u32()?;
        let rdlen = usize::from(self.u16()?);
        let start = self.pos;
        let end = start + rdlen;
        if end > self.buf.len() {
            return Err(WireError("truncated rdata"));
        }
        let data = match rtype {
            TYPE_A => {
                let b = self.take(rdlen)?;
                let b: [u8; 4] = b.try_into().map_err(|_| WireError("bad A length"))?;
                RData::A(Ipv4Addr::from(b))
            }
            TYPE_AAAA => {
                let b = self.take(rdlen)?;
                let b: [u8; 16] = b.try_into().map_err(|_| WireError("bad AAAA length"))?;
                RData::Aaaa(Ipv6Addr::from(b))
            }
            TYPE_CNAME | TYPE_NS | TYPE_PTR => RData::Name(self.name()?),
            TYPE_MX => {
                let pref = self.u16()?;
                RData::Mx(pref, self.name()?)
            }
            TYPE_SRV => RData::Srv {
                priority: self.u16()?,
                weight: self.u16()?,
                port: self.u16()?,
                target: self.name()?,
            },
            _ => RData::Raw(self.take(rdlen)?.to_vec()),
        };
        if self.pos != end {
            return Err(WireError("rdata length mismatch"));
        }
        Ok(Record {
            name,
            rtype,
            class,
            ttl,
            data,
        })
    }
}

/// Parse a whole message. Authority records are skipped; OPT is read for its UDP size.
pub(crate) fn parse(buf: &[u8]) -> Result<Message, WireError> {
    let mut r = Reader { buf, pos: 0 };
    let id = r.u16()?;
    let flags = r.u16()?;
    let qd = r.u16()?;
    let an = r.u16()?;
    let ns = r.u16()?;
    let ar = r.u16()?;
    if qd > 4 {
        return Err(WireError("too many questions"));
    }
    let mut questions = Vec::with_capacity(usize::from(qd));
    for _ in 0..qd {
        questions.push(r.question()?);
    }
    let mut answers = Vec::new();
    for _ in 0..an {
        answers.push(r.record()?);
    }
    for _ in 0..ns {
        r.record()?;
    }
    let mut edns_udp_size = None;
    for _ in 0..ar {
        let record = r.record()?;
        if record.rtype == TYPE_OPT {
            edns_udp_size = Some(record.class.max(512));
        }
    }
    Ok(Message {
        id,
        flags,
        questions,
        answers,
        edns_udp_size,
    })
}

/// Parse just the ID, for a FORMERR reply to a message that does not parse.
pub(crate) fn peek_id(buf: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]))
}

/// The size of EDNS buffer the proxy advertises and honours (DNS flag day 2020).
pub(crate) const EDNS_UDP_SIZE: u16 = 1232;

pub(crate) fn build_query(id: u16, question: &Question) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    question.name.encode(&mut out);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
    encode_opt(&mut out);
    out
}

fn encode_opt(out: &mut Vec<u8>) {
    out.push(0); // root name
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
}

/// A response the proxy writes to a guest.
pub(crate) struct Reply<'a> {
    pub(crate) id: u16,
    pub(crate) recursion_desired: bool,
    pub(crate) rcode: u8,
    pub(crate) question: Option<&'a Question>,
    pub(crate) answers: &'a [Record],
    pub(crate) edns: bool,
}

impl Reply<'_> {
    /// Encode, setting TC and dropping the answers when they would not fit in `limit` bytes.
    pub(crate) fn encode(&self, limit: usize) -> Vec<u8> {
        let full = self.encode_with(self.answers, false);
        if full.len() <= limit {
            return full;
        }
        self.encode_with(&[], true)
    }

    fn encode_with(&self, answers: &[Record], truncated: bool) -> Vec<u8> {
        let mut flags: u16 = 0x8000 | 0x0080 | u16::from(self.rcode & 0x0f); // QR, RA
        if self.recursion_desired {
            flags |= 0x0100;
        }
        if truncated {
            flags |= 0x0200;
        }
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&u16::from(self.question.is_some()).to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&u16::from(self.edns).to_be_bytes());
        if let Some(q) = self.question {
            q.name.encode(&mut out);
            out.extend_from_slice(&q.qtype.to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }
        for record in answers {
            encode_record(record, &mut out);
        }
        if self.edns {
            encode_opt(&mut out);
        }
        out
    }
}

fn encode_record(record: &Record, out: &mut Vec<u8>) {
    record.name.encode(out);
    out.extend_from_slice(&record.rtype.to_be_bytes());
    out.extend_from_slice(&record.class.to_be_bytes());
    out.extend_from_slice(&record.ttl.to_be_bytes());
    let len_at = out.len();
    out.extend_from_slice(&[0, 0]);
    match &record.data {
        RData::A(ip) => out.extend_from_slice(&ip.octets()),
        RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
        RData::Name(name) => name.encode(out),
        RData::Mx(pref, name) => {
            out.extend_from_slice(&pref.to_be_bytes());
            name.encode(out);
        }
        RData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            target.encode(out);
        }
        RData::Raw(bytes) => out.extend_from_slice(bytes),
    }
    let rdlen = (out.len() - len_at - 2) as u16;
    out[len_at..len_at + 2].copy_from_slice(&rdlen.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(name: &str, qtype: u16) -> Question {
        Question {
            name: Name::from_hostname(name).unwrap(),
            qtype,
            qclass: CLASS_IN,
        }
    }

    #[test]
    fn query_round_trips() {
        let q = question("Api.Example.com", TYPE_AAAA);
        let bytes = build_query(0x1234, &q);
        let msg = parse(&bytes).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert!(msg.recursion_desired());
        assert_eq!(msg.questions, vec![q]);
        assert_eq!(msg.questions[0].name.hostname().unwrap(), "api.example.com");
        assert_eq!(msg.edns_udp_size, Some(EDNS_UDP_SIZE));
    }

    #[test]
    fn reply_round_trips_every_record_shape() {
        let q = question("example.com", TYPE_SRV);
        let answers = vec![
            Record {
                name: q.name.clone(),
                rtype: TYPE_A,
                class: CLASS_IN,
                ttl: 30,
                data: RData::A(Ipv4Addr::new(1, 2, 3, 4)),
            },
            Record {
                name: q.name.clone(),
                rtype: TYPE_SRV,
                class: CLASS_IN,
                ttl: 30,
                data: RData::Srv {
                    priority: 1,
                    weight: 2,
                    port: 27017,
                    target: Name::from_hostname("db.example.com").unwrap(),
                },
            },
            Record {
                name: q.name.clone(),
                rtype: TYPE_TXT,
                class: CLASS_IN,
                ttl: 30,
                data: RData::Raw(b"\x05hello".to_vec()),
            },
        ];
        let reply = Reply {
            id: 7,
            recursion_desired: true,
            rcode: RCODE_NOERROR,
            question: Some(&q),
            answers: &answers,
            edns: false,
        };
        let msg = parse(&reply.encode(4096)).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.answers, answers);
        let truncated = parse(&reply.encode(40)).unwrap();
        assert!(truncated.truncated());
        assert!(truncated.answers.is_empty());
    }

    #[test]
    fn follows_backward_pointers_and_rejects_loops() {
        // Header (1 question, 1 answer), question example.com A, answer name = pointer to 12.
        let q = question("example.com", TYPE_A);
        let mut bytes = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        q.name.encode(&mut bytes);
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 9, 9, 9]);
        let msg = parse(&bytes).unwrap();
        assert_eq!(msg.answers[0].name, q.name);
        assert_eq!(msg.answers[0].data, RData::A(Ipv4Addr::new(9, 9, 9, 9)));

        // A pointer to itself.
        let mut looped = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        looped.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(parse(&looped).is_err());
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed: u32 = 0x1234_5678;
        for len in 0..200 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 17;
                    seed ^= seed << 5;
                    seed as u8
                })
                .collect();
            let _ = parse(&bytes);
        }
    }
}
