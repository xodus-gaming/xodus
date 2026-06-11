use crate::models::xvd::constants::{
    BLOCK_SIZE, DATA_BLOCKS_IN_LEVEL0_HASHTREE, DATA_BLOCKS_IN_LEVEL1_HASHTREE,
    DATA_BLOCKS_IN_LEVEL2_HASHTREE, DATA_BLOCKS_IN_LEVEL3_HASHTREE, HASH_ENTRIES_IN_PAGE,
    LEGACY_SECTOR_SIZE, PAGE_SIZE, SECTOR_SIZE,
};

pub fn bytes_to_pages(bytes: u64) -> u64 {
    (bytes + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64
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

pub fn calculate_number_of_hash_blocks_in_level(
    size: u64,
    hash_level: u64,
    resilient: bool,
) -> u64 {
    let hash_blocks = match hash_level {
        0 => {
            (size + DATA_BLOCKS_IN_LEVEL0_HASHTREE as u64 - 1)
                / DATA_BLOCKS_IN_LEVEL0_HASHTREE as u64
        }
        1 => {
            (size + DATA_BLOCKS_IN_LEVEL1_HASHTREE as u64 - 1)
                / DATA_BLOCKS_IN_LEVEL1_HASHTREE as u64
        }
        2 => {
            (size + DATA_BLOCKS_IN_LEVEL2_HASHTREE as u64 - 1)
                / DATA_BLOCKS_IN_LEVEL2_HASHTREE as u64
        }
        3 => {
            (size + DATA_BLOCKS_IN_LEVEL3_HASHTREE as u64 - 1)
                / DATA_BLOCKS_IN_LEVEL3_HASHTREE as u64
        }
        _ => unreachable!("There are 3 levels"),
    };

    if resilient {
        return hash_blocks * 2;
    }

    hash_blocks
}

pub fn calculate_number_of_hash_pages(hashed_pages_count: u64, resilient: bool) -> (u64, u64) {
    let mut hash_tree_levels = 1;
    let mut hash_tree_pages =
        (hashed_pages_count + HASH_ENTRIES_IN_PAGE as u64 - 1) / HASH_ENTRIES_IN_PAGE as u64;
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
