fn main() {
    // The helper uses RocksDB's C++ implementation. Also link libc++ when
    // librocksdb-sys uses its supported prebuilt-static-library path, which
    // skips cc's usual automatic C++ runtime link directive.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=c++");
    }
}
