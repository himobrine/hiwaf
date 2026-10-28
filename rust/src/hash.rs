//! 纯 Rust SHA-1（**零新依赖**）。
//!
//! 用途只有两个，都是「变没变」的指纹，不是安全原语：
//!   1. 采集器每 5s 轮询 `decision_policy.json` / `rules_authoritative.json` 的 sha1；
//!   2. 事件里记 `rule_set_sha1_16`，让控制台能核对"这条记录是哪一版规则判的"。
//!
//! 之所以自己写：引入 `sha1` crate 会破坏"热重载零新依赖"的约束（ort 已经很大）。
//! 正确性由 `python/calibrate_rules.py` 与 `export_rules_testvec.py` 用
//! `hashlib.sha1(...).hexdigest()[:16]` 交叉核对，**不靠"看起来对"**。

const H0: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = H0;
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut msg: Vec<u8> = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for i in 0..5 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

/// 取 `hexdigest()[:16]` —— 与 Python `hashlib.sha1(b).hexdigest()[:16]` 一致。
pub fn sha1_16(data: &[u8]) -> String {
    sha1(data)[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// 直接对文件算指纹（读不到返回 None）。
pub fn sha1_16_file(path: &std::path::Path) -> Option<String> {
    std::fs::read(path).ok().map(|b| sha1_16(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(sha1_16(b""), "da39a3ee5e6b4b0d");
        assert_eq!(sha1_16(b"abc"), "a9993e364706816a");
        assert_eq!(sha1_16(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
                   "84983e441c3bd26e");
        // 恰好跨 padding / 分块边界（55、56 会在补位时多出一个块）
        assert_eq!(sha1_16(&vec![b'a'; 54]), "b05d71c64979cb95");
        assert_eq!(sha1_16(&vec![b'a'; 55]), "c1c8bbdc22796e28");
        assert_eq!(sha1_16(&vec![b'a'; 56]), "c2db330f6083854c");
        assert_eq!(sha1_16(&vec![b'a'; 63]), "03f09f5b158a7a8c");
        assert_eq!(sha1_16(&vec![b'a'; 64]), "0098ba824b5c1642");
        assert_eq!(sha1_16(&vec![b'a'; 65]), "11655326c708d703");
    }
}
