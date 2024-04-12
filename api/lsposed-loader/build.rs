use std::env;
use glob::glob;

fn main() {
    // https://github.com/rusqlite/rusqlite/issues/1380#issuecomment-1689765485
    if env::var("TARGET") == Ok("x86_64-linux-android".into()) {
        let android_ndk = env::var("ANDROID_NDK").unwrap();

        let pattern = format!("{android_ndk}/toolchains/llvm/prebuilt/*/lib/clang/*/lib/linux");
        let link_search: String = glob(&pattern).unwrap()
            .flatten()
            .last().unwrap()
            .to_str().unwrap()
            .into();

        println!("cargo:rustc-link-lib=static=clang_rt.builtins-x86_64-android");
        println!("cargo:rustc-link-search={link_search}");
    }
}
