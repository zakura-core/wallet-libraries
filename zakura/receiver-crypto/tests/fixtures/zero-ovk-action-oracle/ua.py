"""Splits a Zcash unified address into (typecode, receiver bytes) pairs (ZIP 316)."""
import hashlib

CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32m_decode(s):
    hrp, data = s.rsplit('1', 1)
    values = [CHARSET.index(c) for c in data]
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _polymod(expand + values) != 0x2bc830a3:
        raise ValueError('bad checksum')
    acc, bits, out = 0, 0, []
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xff)
    return hrp, bytes(out)


def _h(i, u, n):
    return hashlib.blake2b(u, digest_size=n, person=b'UA_F4Jumble_H' + bytes([i, 0, 0])).digest()


def _g(i, u, n):
    out = b''
    j = 0
    while len(out) < n:
        out += hashlib.blake2b(u, digest_size=64, person=b'UA_F4Jumble_G' + bytes([i]) + j.to_bytes(2, 'little')).digest()
        j += 1
    return out[:n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _f4unjumble(m):
    ll = min(64, len(m) // 2)
    lr = len(m) - ll
    c, d = m[:ll], m[ll:]
    y = _xor(c, _h(1, d, ll))
    x = _xor(d, _g(1, y, lr))
    a = _xor(y, _h(0, x, ll))
    b = _xor(x, _g(0, a, lr))
    return a + b


def _compact(buf, i):
    v = buf[i]
    if v < 0xfd:
        return v, i + 1
    n = {0xfd: 2, 0xfe: 4, 0xff: 8}[v]
    return int.from_bytes(buf[i + 1:i + 1 + n], 'little'), i + 1 + n


def receivers(address):
    """Returns [(typecode, bytes)] for a mainnet unified address."""
    hrp, raw = _bech32m_decode(address)
    m = _f4unjumble(raw)
    pad = hrp.encode().ljust(16, b'\0')
    if m[-16:] != pad:
        raise ValueError('bad padding')
    m, i, out = m[:-16], 0, []
    while i < len(m):
        t, i = _compact(m, i)
        n, i = _compact(m, i)
        out.append((t, m[i:i + n]))
        i += n
    return out


if __name__ == '__main__':
    import sys
    for t, r in receivers(sys.argv[1]):
        print(t, len(r), r.hex()[:16] + '...')
