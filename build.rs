#[cfg(target_os = "windows")]
extern crate embed_resource;

#[cfg(target_os = "windows")]
fn main() {
    println!("cargo:rerun-if-changed=productinfo.rc");
    println!("cargo:rerun-if-changed=win_icon.ico"); // Or actual icon path

    let _ = embed_resource::compile("productinfo.rc", embed_resource::NONE);
}

// This empty main function will be compiled and run on ALL OTHER platforms
// (Linux, macOS, etc.)
#[cfg(not(target_os = "windows"))]
fn main() {
    // Do nothing
}