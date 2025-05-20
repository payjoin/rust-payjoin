pub type OutputSubstitution = payjoin::OutputSubstitution;

#[cfg(feature = "uniffi")]
#[cfg_attr(feature = "uniffi", uniffi::remote(Enum))]
enum OutputSubstitution {
    Enabled,
    Disabled,
}
