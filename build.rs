//! Gives the certval binary's main thread an 8 MB stack on Windows, the size macOS and Linux give it.
//! Windows reserves 1 MB, which ML-DSA signing overflows in an unoptimized build. Set at link time,
//! so it holds for `cargo install` as well as for a checkout.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/STACK:8388608");
    } else {
        println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608");
    }
}
