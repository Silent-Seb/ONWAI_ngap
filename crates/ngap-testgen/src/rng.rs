/// xorshift64*: small, deterministic, good enough for test data.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        // splitmix the seed so that small seeds give unrelated streams, and never start at 0
        let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Rng((z ^ (z >> 31)) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `0..n` (`n > 0`; slightly biased for huge `n`, which does not matter here).
    pub fn below(&mut self, n: u128) -> u128 {
        let wide = (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64());
        wide % n
    }

    /// Uniform in `lo..=hi`.
    pub fn between(&mut self, lo: i128, hi: i128) -> i128 {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u128 + 1;
        if span == 0 {
            return lo;
        }
        lo + self.below(span) as i128
    }

    pub fn chance(&mut self, one_in: u64) -> bool {
        self.next_u64().is_multiple_of(one_in)
    }
}

/// FNV-1a: a stable hash of a name, used to derive per-vector seeds.
pub fn hash(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
