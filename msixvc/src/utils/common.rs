#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl std::cmp::Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
            .then(self.build.cmp(&other.build))
    }
}

impl std::cmp::PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the Display implementation as the Debug one
        write!(f, "{}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_cmp() {
        let lower = Version {
            major: 1,
            minor: 26,
            patch: 3005,
            build: 0,
        };
        let higher = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high = Version {
            major: 1,
            minor: 26,
            patch: 3101,
            build: 0,
        };
        let other_high2 = Version {
            major: 2,
            minor: 26,
            patch: 3101,
            build: 0,
        };

        assert!(lower < higher);
        assert!(higher > lower);
        assert!(higher == other_high);
        assert!(other_high2 > other_high);
    }
}
