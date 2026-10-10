//! Reading the address an input spends from its unlocking script alone.

use transparent::address::TransparentAddress;

/// The pushes of a push-only script, or `None` when it is malformed or not push-only. A small
/// number opcode (`OP_1NEGATE`, `OP_1` to `OP_16`) pushes its opcode byte.
pub(super) fn pushes(script: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let (len, tail) = match op {
            0x00..=0x4b => (usize::from(op), tail),
            0x4c => (usize::from(*tail.first()?), &tail[1..]),
            0x4d => (
                usize::from(u16::from_le_bytes(tail.get(..2)?.try_into().ok()?)),
                &tail[2..],
            ),
            0x4e => (
                usize::try_from(u32::from_le_bytes(tail.get(..4)?.try_into().ok()?)).ok()?,
                &tail[4..],
            ),
            0x4f | 0x51..=0x60 => {
                out.push(&rest[..1]);
                rest = tail;
                continue;
            }
            _ => return None,
        };
        out.push(tail.get(..len)?);
        rest = &tail[len..];
    }
    Some(out)
}

/// The last opcode of a well-formed script: every push is within the script.
pub(super) fn last_opcode(script: &[u8]) -> Option<u8> {
    let mut last = None;
    let mut rest = script;
    while let Some((&op, tail)) = rest.split_first() {
        let skip = match op {
            0x01..=0x4b => usize::from(op),
            0x4c => 1 + usize::from(*tail.first()?),
            0x4d => 2 + usize::from(u16::from_le_bytes(tail.get(..2)?.try_into().ok()?)),
            0x4e => {
                4 + usize::try_from(u32::from_le_bytes(tail.get(..4)?.try_into().ok()?)).ok()?
            }
            _ => 0,
        };
        rest = tail.get(skip..)?;
        last = Some(op);
    }
    last
}

/// The address an input spends, read from its unlocking script alone, without the spent output.
///
/// A P2PKH spend is a signature and then a 33-byte compressed or 65-byte uncompressed public
/// key; its address is the key's HASH160. A P2SH spend pushes its redeem script last, after at
/// least one other push; the redeem script must be well formed and end in a signature check
/// (`OP_CHECKSIG`, `OP_CHECKMULTISIG` or their `VERIFY` forms), which tells it apart from a
/// signature. Anything else has no address here.
///
/// Without the spent output this is a reading, not a proof: a P2SH redeem script shaped like
/// a public key reads as P2PKH, and a non-standard locking script can accept any key. So a
/// raw transaction's sender is never taken as the account's own on this alone.
pub(super) fn spent_address(script_sig: &[u8]) -> Option<TransparentAddress> {
    let pushes = pushes(script_sig)?;
    let is_signature = |sig: &[u8]| (9..=73).contains(&sig.len()) && sig[0] == 0x30;
    let is_key = |key: &[u8]| {
        (key.len() == 33 && matches!(key[0], 0x02 | 0x03)) || (key.len() == 65 && key[0] == 0x04)
    };
    match pushes.as_slice() {
        [sig, key] if is_signature(sig) && is_key(key) => Some(TransparentAddress::PublicKeyHash(
            transparent::util::hash160::hash(key),
        )),
        [_, .., redeem] if matches!(last_opcode(redeem), Some(0xac..=0xaf)) => Some(
            TransparentAddress::ScriptHash(transparent::util::hash160::hash(redeem)),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(data: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 75);
        [&[data.len() as u8][..], data].concat()
    }

    fn signature() -> Vec<u8> {
        let mut sig = vec![0x30; 71];
        sig[70] = 0x01;
        sig
    }

    #[test]
    fn spent_address_from_unlocking_scripts() {
        use transparent::util::hash160::hash;
        let key = [&[0x02][..], &[7; 32]].concat();
        let p2pkh = [push(&signature()), push(&key)].concat();
        assert_eq!(
            spent_address(&p2pkh),
            Some(TransparentAddress::PublicKeyHash(hash(&key)))
        );
        let uncompressed = [&[0x04][..], &[7; 64]].concat();
        assert_eq!(
            spent_address(&[push(&signature()), push(&uncompressed)].concat()),
            Some(TransparentAddress::PublicKeyHash(hash(&uncompressed)))
        );
        // 2-of-2 multisig P2SH: OP_0, two signatures, the redeem script.
        let redeem = [
            &[0x52][..],
            &push(&key),
            &push(&[&[0x03][..], &[8; 32]].concat()),
            &[0x52, 0xae],
        ]
        .concat();
        let p2sh = [
            &[0x00][..],
            &push(&signature()),
            &push(&signature()),
            &[0x4c, redeem.len() as u8],
            &redeem,
        ]
        .concat();
        assert_eq!(
            spent_address(&p2sh),
            Some(TransparentAddress::ScriptHash(hash(&redeem)))
        );
        // A lone signature (P2PK), a non-push opcode, a truncated push, an empty script, and a
        // last push that does not end in a signature check have no address.
        for none in [
            push(&signature()),
            [push(&signature()), vec![0xac]].concat(),
            vec![0x05, 0x01],
            vec![],
            [push(&signature()), push(&[0x51, 0x87])].concat(),
            [push(&signature()), push(&[0x02; 20])].concat(),
        ] {
            assert_eq!(spent_address(&none), None, "{none:x?}");
        }
    }
}
