/// Whether the receiver is allowed to substitute original outputs or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum OutputSubstitution {
    Enabled,
    Disabled,
}
