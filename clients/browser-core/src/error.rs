//! Classify failures at their source. Only the stable code crosses into Wasm.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    Authentication,
    Password,
    Backup,
    Network,
    Configuration,
    Locked,
    Recovery,
    History,
    SyncRequired,
    Review,
    Internal,
}

#[derive(Debug)]
pub struct BrowserError {
    code: ErrorCode,
    detail: String,
}

impl BrowserError {
    pub(crate) fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self.code {
            ErrorCode::Authentication => "authentication",
            ErrorCode::Password => "password",
            ErrorCode::Backup => "backup",
            ErrorCode::Network => "network",
            ErrorCode::Configuration => "configuration",
            ErrorCode::Locked => "locked",
            ErrorCode::Recovery => "recovery",
            ErrorCode::History => "history",
            ErrorCode::SyncRequired => "sync_required",
            ErrorCode::Review => "review",
            ErrorCode::Internal => "internal",
        }
    }

    #[cfg(any(test, target_arch = "wasm32"))]
    fn wire_code(&self) -> String {
        format!("zolana-wallet-error-v1:{}", self.code())
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn into_js(self) -> wasm_bindgen::JsValue {
        wasm_bindgen::JsValue::from_str(&self.wire_code())
    }
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for BrowserError {}

impl From<String> for BrowserError {
    fn from(detail: String) -> Self {
        Self::new(ErrorCode::Internal, detail)
    }
}

impl From<&str> for BrowserError {
    fn from(detail: &str) -> Self {
        Self::new(ErrorCode::Internal, detail)
    }
}

impl From<native_wallet_seed::Error> for BrowserError {
    fn from(error: native_wallet_seed::Error) -> Self {
        use native_wallet_seed::Error;
        let code = match error {
            Error::InvalidPassword => ErrorCode::Password,
            Error::InvalidNetwork => ErrorCode::Configuration,
            Error::EnvelopeTooLarge | Error::InvalidEnvelope => ErrorCode::Backup,
            Error::FormatOrNetworkMismatch => ErrorCode::Network,
            Error::Authentication => ErrorCode::Authentication,
        };
        Self::new(code, error.to_string())
    }
}

/// Result type for opaque browser-wallet operations.
pub type Result<T> = std::result::Result<T, BrowserError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_code_is_independent_of_diagnostic_text() {
        let typed = BrowserError::new(ErrorCode::Locked, "different diagnostic wording");
        assert_eq!(typed.wire_code(), "zolana-wallet-error-v1:locked");
        let unclassified = BrowserError::from("wallet is locked");
        assert_eq!(unclassified.wire_code(), "zolana-wallet-error-v1:internal");
        assert_eq!(unclassified.to_string(), "wallet is locked");
    }
}
