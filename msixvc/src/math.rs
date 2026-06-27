use crate::models::xvd::constants::{
    BLOCK_SIZE, DATA_BLOCKS_IN_LEVEL0_HASHTREE, DATA_BLOCKS_IN_LEVEL1_HASHTREE,
    DATA_BLOCKS_IN_LEVEL2_HASHTREE, DATA_BLOCKS_IN_LEVEL3_HASHTREE, HASH_ENTRIES_IN_PAGE,
    LEGACY_SECTOR_SIZE, PAGE_SIZE, PAGES_PER_BLOCK, SECTOR_SIZE,
};

pub fn bytes_to_pages(bytes: u64) -> u64 {
    bytes.div_ceil(PAGE_SIZE as u64)
}

pub fn offset_to_block_number(offset: u64) -> u64 {
    offset / BLOCK_SIZE as u64
}

pub fn offset_to_page_number(offset: u64) -> u64 {
    offset / PAGE_SIZE as u64
}

pub fn sectors_to_bytes(sectors: u64) -> u64 {
    sectors * SECTOR_SIZE as u64
}

pub fn legacy_sectors_to_bytes(sectors: u64) -> u64 {
    sectors * LEGACY_SECTOR_SIZE as u64
}

pub fn page_number_to_offset(page_number: u64) -> u64 {
    page_number * PAGE_SIZE as u64
}

pub fn calculate_hash_block_num_and_run_for_block_num(
    xvd_type: u32,
    hash_tree_levels: u64,
    number_of_hashed_pages: u64,
    block_num: u64,
    hash_level: u32,
    resilient: bool,
    unknown: bool,
) -> (u64, u64, u64) {
    fn hash_block_exponent(block_count: u32) -> u64 {
        (PAGES_PER_BLOCK as u64).pow(block_count)
    }

    if xvd_type > 1 || hash_level > 3 {
        return (0xFFFF, 0, 1);
    }

    let entry_num_in_block = (block_num / hash_block_exponent(hash_level)) % PAGES_PER_BLOCK as u64;
    let run_length = PAGES_PER_BLOCK as u64 - entry_num_in_block;

    if hash_level == 3 {
        return (0, entry_num_in_block, run_length);
    }

    let mut result = block_num / hash_block_exponent(hash_level + 1);
    let mut remaining_hash_tree_levels = hash_tree_levels - u64::from(hash_level + 1);

    if hash_level == 0 && remaining_hash_tree_levels > 0 {
        result += number_of_hashed_pages.div_ceil(hash_block_exponent(2));
        remaining_hash_tree_levels -= 1;
    }

    if (hash_level == 0 || hash_level == 1) && remaining_hash_tree_levels > 0 {
        result += number_of_hashed_pages.div_ceil(hash_block_exponent(3));
        remaining_hash_tree_levels -= 1;
    }

    if remaining_hash_tree_levels > 0 {
        result += number_of_hashed_pages.div_ceil(hash_block_exponent(4));
    }

    if resilient {
        result *= 2;
    }

    if unknown {
        result += 1;
    }

    (result, entry_num_in_block, run_length)
}

pub fn calculate_number_of_hash_blocks_in_level(
    size: u64,
    hash_level: u64,
    resilient: bool,
) -> u64 {
    let hash_blocks = match hash_level {
        0 => size.div_ceil(DATA_BLOCKS_IN_LEVEL0_HASHTREE as u64),
        1 => size.div_ceil(DATA_BLOCKS_IN_LEVEL1_HASHTREE as u64),
        2 => size.div_ceil(DATA_BLOCKS_IN_LEVEL2_HASHTREE as u64),
        3 => size.div_ceil(DATA_BLOCKS_IN_LEVEL3_HASHTREE as u64),
        _ => unreachable!("There are 3 levels"),
    };

    if resilient {
        return hash_blocks * 2;
    }

    hash_blocks
}

pub fn calculate_number_of_hash_pages(hashed_pages_count: u64, resilient: bool) -> (u64, u64) {
    let mut hash_tree_levels = 1;
    let mut hash_tree_pages = hashed_pages_count.div_ceil(HASH_ENTRIES_IN_PAGE as u64);
    if hash_tree_pages > 1 {
        let mut result = 2;
        while result > 1 {
            result = calculate_number_of_hash_blocks_in_level(
                hashed_pages_count,
                hash_tree_levels,
                false,
            );
            hash_tree_levels += 1;
            hash_tree_pages += result;
        }
    }

    if resilient {
        hash_tree_pages *= 2;
    }

    (hash_tree_levels, hash_tree_pages)
}

/// Multiplies a polynomial by `x` in the Galois field `GF(2^128)` modulo
/// `x¹²⁸ + x⁷ + x² + x + 1`, the irreducible polynomial used by XTS-AES.
#[inline]
#[must_use = "unused arithmetic operation that must be used"]
pub const fn gf_mul_x(n: u128) -> u128 {
    // Shift all bits left by 1. If it overflows, XOR the result with the
    // field's irreducible polynomial (excluding the leading term).

    /// The irreducible polynomial used by XTS-AES: `x¹²⁸ + x⁷ + x² + x + 1`.
    /// The leading term `x¹²⁸` is implicit in the overflow bit and excluded here.
    const IRREDUCIBLE_POLYNOMIAL: u128 = 0x87;

    // If the high bit is set, then the mask is the irreducible polynomial
    // (excluding the leading term). If the high bit is not set, the mask is 0.
    let mask = (n >> 127).wrapping_neg() & IRREDUCIBLE_POLYNOMIAL;

    // Shift left and apply the mask.
    (n << 1) ^ mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_x_test() {
        // 0 * x = 0
        assert_eq!(gf_mul_x(0), 0);

        // 1 * x = x
        assert_eq!(gf_mul_x(1), 2);

        // High bit not set, so just a left shift.
        assert_eq!(gf_mul_x(0b101), 0b1010);

        // High bit set, so result must be reduced by XORing 0x87.
        assert_eq!(gf_mul_x(1u128 << 127), 0x87);

        // All bits are set: the shift overflows and the result is reduced.
        assert_eq!(gf_mul_x(u128::MAX), (u128::MAX << 1) ^ 0x87);
    }
}
