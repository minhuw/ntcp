use core::arch::x86_64::*;

// cpufeatures 0.2 uses the pre-associated-constant spelling of u8::MAX.
#[allow(deprecated)]
mod detect {
    cpufeatures::new!(avx2, "avx2");

    pub(crate) use avx2::get as has_avx2;
}

pub(super) use detect::has_avx2;

// SAFETY: callers must establish that the CPU and OS support AVX2.
#[target_feature(enable = "avx2")]
pub(super) fn checksum(bytes: &[u8], prefix: u64) -> u16 {
    let (pairs, tail) = bytes.as_chunks::<64>();
    let mut sum = (prefix & 0xffff_ffff) + (prefix >> 32);
    let bias = _mm256_set1_epi16(i16::MIN);
    let ones = _mm256_set1_epi16(1);

    // A 64 KiB run contains at most 32768 unsigned words. Its complete
    // unbiased sum fits in u32, including when every word is 0xffff.
    for run in pairs.chunks(1024) {
        let mut first = _mm256_setzero_si256();
        let mut second = first;
        for pair in run {
            // SAFETY: pair has 64 initialized bytes and the two unaligned
            // vector loads each read exactly one 32-byte half of it.
            let (a, b) = unsafe {
                let start = pair.as_ptr().cast::<__m256i>();
                (_mm256_loadu_si256(start), _mm256_loadu_si256(start.add(1)))
            };
            first = _mm256_add_epi32(first, _mm256_madd_epi16(_mm256_xor_si256(a, bias), ones));
            second = _mm256_add_epi32(second, _mm256_madd_epi16(_mm256_xor_si256(b, bias), ones));
        }
        let both = _mm256_add_epi32(first, second);
        let halves = _mm_add_epi32(
            _mm256_castsi256_si128(both),
            _mm256_extracti128_si256::<1>(both),
        );
        let quarters = _mm_add_epi32(halves, _mm_srli_si128::<8>(halves));
        let lanes = _mm_add_epi32(quarters, _mm_srli_si128::<4>(quarters));
        let words = (_mm_cvtsi128_si32(lanes) as u32).wrapping_add(run.len() as u32 * 32 * 32768);

        // Multiplication by 256 exchanges native and network byte order
        // modulo 65535. checksum_block bounded this input to at most 1 GiB.
        sum += u64::from(words) << 8;
    }
    super::checksum_scalar(tail, sum)
}
