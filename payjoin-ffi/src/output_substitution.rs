pub type OutputSubstitution = payjoin::OutputSubstitution;

#[uniffi::remote(Enum)]
enum OutputSubstitution {
    Enabled,
    Disabled,
}
