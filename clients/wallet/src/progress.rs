//! Optional device-local progress. Never emits keys, proof bytes or payment details.
pub fn report(phase: &str) {
    if std::env::var_os("NATIVE_WALLET_PROGRESS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        println!("{}", serde_json::json!({"wallet_progress": phase}));
    }
}
