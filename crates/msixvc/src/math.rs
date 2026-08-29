use crate::layout::Pages;
use crate::models::xvd::{
    DATA_BLOCKS_IN_LEVEL0_HASHTREE, DATA_BLOCKS_IN_LEVEL1_HASHTREE, DATA_BLOCKS_IN_LEVEL2_HASHTREE,
    DATA_BLOCKS_IN_LEVEL3_HASHTREE, HASH_ENTRIES_IN_PAGE, PAGES_PER_BLOCK,
};

pub fn calculate_hash_block_num_and_run_for_block_num(
    xvd_type: u32,
    hash_tree_levels: u64,
    number_of_hashed_pages: Pages,
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
        result += number_of_hashed_pages.0.div_ceil(hash_block_exponent(2));
        remaining_hash_tree_levels -= 1;
    }

    if (hash_level == 0 || hash_level == 1) && remaining_hash_tree_levels > 0 {
        result += number_of_hashed_pages.0.div_ceil(hash_block_exponent(3));
        remaining_hash_tree_levels -= 1;
    }

    if remaining_hash_tree_levels > 0 {
        result += number_of_hashed_pages.0.div_ceil(hash_block_exponent(4));
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
