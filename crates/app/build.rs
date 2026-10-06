//! Build script: embed the application icon into the Windows executable.
//!
//! The icon is only embedded when the compilation target is Windows. Explorer
//! and shortcut icons read it from the executable resource, while the runtime
//! window icon is set in `main.rs`. A missing resource toolchain (for example
//! during some cross builds) is reported as a warning instead of failing the
//! build.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    // Re-run when the icon changes so a rebuilt executable picks it up.
    println!("cargo:rerun-if-changed=../../assets/icon.ico");

    let mut resource = winresource::WindowsResource::new();
    resource.set_icon("../../assets/icon.ico");
    if let Err(err) = resource.compile() {
        println!("cargo:warning=failed to embed the Windows application icon: {err}");
    }
}
