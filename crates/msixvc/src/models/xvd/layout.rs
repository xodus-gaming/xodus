use super::XvdHeader;
use crate::layout::{Bytes, PAGE_SIZE, Pages};

#[derive(Clone, Copy, Debug)]
pub struct XvdSection {
    pub start: Pages,
    pub len: Bytes,
}

#[derive(Clone, Copy, Debug)]
pub struct XvdLayout {
    // It is guaranteed that no sections overlap.
    header: XvdSection,
    embedded_xvd: XvdSection,
    mutable_data: XvdSection,
    hash_tree: XvdSection,
    user_data: XvdSection,
    xvc_info: XvdSection,
    dynamic_header: XvdSection,
    drive_data: XvdSection,
}

impl XvdHeader {
    pub fn layout(&self) -> XvdLayout {
        let mut current_page = Pages(0);
        let mut next_section = |len: Bytes| -> XvdSection {
            let section = XvdSection {
                start: current_page,
                len,
            };
            current_page += len.to_page_count();
            section
        };

        let header_section = next_section(Bytes(PAGE_SIZE as u64 * 3));
        let embedded_xvd = next_section(self.embedded_xvd_length);
        let mutable_data = next_section(self.mutable_page_count.to_bytes());
        let hash_tree = todo!();
        let user_data = next_section(self.user_data_length);
        let xvc_info = next_section(self.xvc_data_length);
        let dynamic_header = next_section(self.dynamic_header_length);
        let drive_data = next_section(self.drive_size);

        XvdLayout {
            header: header_section,
            embedded_xvd,
            mutable_data,
            hash_tree,
            user_data,
            xvc_info,
            dynamic_header,
            drive_data,
        }
    }
}

impl XvdLayout {
    pub fn header(&self) -> XvdSection {
        self.header
    }

    pub fn embedded_xvd(&self) -> XvdSection {
        self.embedded_xvd
    }

    pub fn mutable_data(&self) -> XvdSection {
        self.mutable_data
    }

    pub fn hash_tree(&self) -> XvdSection {
        self.hash_tree
    }

    pub fn user_data(&self) -> XvdSection {
        self.user_data
    }

    pub fn xvc_info(&self) -> XvdSection {
        self.xvc_info
    }

    pub fn dynamic_header(&self) -> XvdSection {
        self.dynamic_header
    }

    pub fn drive_data(&self) -> XvdSection {
        self.drive_data
    }
}
