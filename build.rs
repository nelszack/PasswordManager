//! Windows gives the main thread a 1 MiB stack. Walking the whole command tree
//! (shell completions, the generated command reference) can exceed that in a
//! debug build, so the `pm` executable reserves 8 MiB, the Linux and macOS
//! default. Linker arguments from here apply even when RUSTFLAGS is set.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
            println!("cargo:rustc-link-arg-bins=/STACK:8388608");
        } else {
            println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608");
        }
    }
}
