/// Whether the receiver is allowed to substitute original outputs or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "v2", derive(serde::Serialize, serde::Deserialize))]
pub enum OutputSubstitution {
    Enabled,
    Disabled,
}

impl OutputSubstitution {
    /// Combine two output substitution flags.
    ///
    /// If both are enabled, the result is enabled.
    /// If one is disabled, the result is disabled.
    pub(crate) fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Enabled, Self::Enabled) => Self::Enabled,
            _ => Self::Disabled,
        }
    }
}
