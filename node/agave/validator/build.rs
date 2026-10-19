fn main() {
    // RocksDB's supported prebuilt-library path skips cc's C++ runtime link
    // directive. macOS validators still require the system libc++ runtime.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=c++");
    }
}
