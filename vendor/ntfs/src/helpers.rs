// Copyright 2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

macro_rules! iter_try {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(e) => return Some(Err(e.into())),
        }
    };
}

#[cfg(test)]
pub mod tests {
    use std::fs::File;
    use std::io::{Cursor, Read};

    pub fn testfs1() -> Cursor<Vec<u8>> {
        let mut buffer = Vec::new();
        File::open("testdata/testfs1")
            .unwrap()
            .read_to_end(&mut buffer)
            .unwrap();
        Cursor::new(buffer)
    }
}
