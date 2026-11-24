//! Just enough DER to read the executor CA: its subject name, public key and subject key ID.
//!
//! The proxy signs leaf certificates with the CA Sealant hands it. A leaf chains to that CA only if
//! its issuer name matches the CA's subject byte for byte and, for OpenSSL clients, its authority
//! key ID matches the CA's subject key ID. rcgen 0.13 reads both only behind its `x509-parser`
//! feature, which would pull a whole ASN.1 stack into a static binary, so this reads them here.

#[derive(Debug, thiserror::Error)]
#[error("malformed certificate DER: {0}")]
pub(crate) struct DerError(&'static str);

pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) raw: &'a [u8],
}

pub(crate) fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    let (&tag, rest) = input.split_first().ok_or(DerError("truncated tag"))?;
    if tag & 0x1f == 0x1f {
        return Err(DerError("multi-byte tags are not supported"));
    }
    let (&first, mut rest) = rest.split_first().ok_or(DerError("truncated length"))?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(DerError("unsupported length"));
        }
        if rest.len() < count {
            return Err(DerError("truncated length"));
        }
        let (bytes, after) = rest.split_at(count);
        rest = after;
        bytes
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b))
    };
    if rest.len() < len {
        return Err(DerError("truncated value"));
    }
    let header_len = input.len() - rest.len();
    let (value, after) = rest.split_at(len);
    Ok((
        Tlv {
            tag,
            value,
            raw: &input[..header_len + len],
        },
        after,
    ))
}

fn expect<'a>(
    input: &'a [u8],
    tag: u8,
    what: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), DerError> {
    let (tlv, rest) = read_tlv(input)?;
    if tlv.tag != tag {
        return Err(DerError(what));
    }
    Ok((tlv, rest))
}

pub(crate) fn decode_oid(bytes: &[u8]) -> Result<Vec<u64>, DerError> {
    let (&first, rest) = bytes.split_first().ok_or(DerError("empty OID"))?;
    let mut arcs = vec![u64::from(first / 40), u64::from(first % 40)];
    let mut value: u64 = 0;
    for &b in rest {
        if value > (u64::MAX >> 7) {
            return Err(DerError("OID arc overflow"));
        }
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    Ok(arcs)
}

/// One attribute of the CA's subject: its OID, the DER string tag and the raw string bytes.
pub(crate) struct NameAttribute {
    pub(crate) oid: Vec<u64>,
    pub(crate) tag: u8,
    pub(crate) value: Vec<u8>,
}

pub(crate) struct CertificateInfo {
    pub(crate) subject: Vec<NameAttribute>,
    /// The full DER of SubjectPublicKeyInfo.
    pub(crate) spki: Vec<u8>,
    pub(crate) subject_key_id: Option<Vec<u8>>,
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const BOOLEAN: u8 = 0x01;
const SUBJECT_KEY_ID: [u64; 4] = [2, 5, 29, 14];

pub(crate) fn parse_certificate(der: &[u8]) -> Result<CertificateInfo, DerError> {
    let (cert, _) = expect(der, SEQUENCE, "certificate is not a SEQUENCE")?;
    let (tbs, _) = expect(cert.value, SEQUENCE, "tbsCertificate is not a SEQUENCE")?;
    let mut rest = tbs.value;
    // [0] EXPLICIT version, optional.
    let (first, after) = read_tlv(rest)?;
    if first.tag == 0xa0 {
        rest = after;
    }
    let (_serial, after) = expect(rest, 0x02, "serialNumber is not an INTEGER")?;
    let (_sig, after) = expect(after, SEQUENCE, "signature is not a SEQUENCE")?;
    let (_issuer, after) = expect(after, SEQUENCE, "issuer is not a SEQUENCE")?;
    let (_validity, after) = expect(after, SEQUENCE, "validity is not a SEQUENCE")?;
    let (subject, after) = expect(after, SEQUENCE, "subject is not a SEQUENCE")?;
    let (spki, mut rest) = expect(after, SEQUENCE, "subjectPublicKeyInfo is not a SEQUENCE")?;

    let mut attributes = Vec::new();
    let mut rdns = subject.value;
    while !rdns.is_empty() {
        let (set, after) = expect(rdns, SET, "RDN is not a SET")?;
        rdns = after;
        let mut atvs = set.value;
        while !atvs.is_empty() {
            let (atv, after) = expect(atvs, SEQUENCE, "attribute is not a SEQUENCE")?;
            atvs = after;
            let (oid, after) = expect(atv.value, OID, "attribute type is not an OID")?;
            let (value, _) = read_tlv(after)?;
            attributes.push(NameAttribute {
                oid: decode_oid(oid.value)?,
                tag: value.tag,
                value: value.value.to_vec(),
            });
        }
    }

    let mut subject_key_id = None;
    while !rest.is_empty() {
        let (field, after) = read_tlv(rest)?;
        rest = after;
        if field.tag != 0xa3 {
            continue;
        }
        let (extensions, _) = expect(field.value, SEQUENCE, "extensions are not a SEQUENCE")?;
        let mut items = extensions.value;
        while !items.is_empty() {
            let (ext, after) = expect(items, SEQUENCE, "extension is not a SEQUENCE")?;
            items = after;
            let (oid, mut body) = expect(ext.value, OID, "extension id is not an OID")?;
            let (next, after) = read_tlv(body)?;
            if next.tag == BOOLEAN {
                body = after;
            }
            let (octets, _) = expect(body, OCTET_STRING, "extension value is not an OCTET STRING")?;
            if decode_oid(oid.value)? == SUBJECT_KEY_ID {
                let (key_id, _) = expect(octets.value, OCTET_STRING, "subjectKeyIdentifier")?;
                subject_key_id = Some(key_id.value.to_vec());
            }
        }
    }

    Ok(CertificateInfo {
        subject: attributes,
        spki: spki.raw.to_vec(),
        subject_key_id,
    })
}
