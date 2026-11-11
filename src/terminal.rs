pub(crate) fn metadata(value: &str) -> zeroize::Zeroizing<String> {
    pm_client::terminal_metadata(value)
}
