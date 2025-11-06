#[cfg(windows)]
fn main() {
    use std::path::Path;

    // Re-run build script if env or icon changes
    println!("cargo:rerun-if-env-changed=HSIP_NO_ICON");

    // Allow disabling icon embedding (useful for CI): HSIP_NO_ICON=1
    let no_icon = std::env::var("HSIP_NO_ICON").ok().as_deref() == Some("1");
    if no_icon {
        return;
    }

    // Prefer repo-root/installer/hsip.ico; fall back to crate-local hsip.ico
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");
    let guess_repo_icon = Path::new(&manifest_dir)
        .join("..").join("..").join("installer").join("hsip.ico");

    let icon_path = if guess_repo_icon.exists() {
        guess_repo_icon
    } else {
        Path::new(&manifest_dir).join("hsip.ico")
    };

    let icon_str = icon_path
        .to_str()
        .expect("icon path is not valid UTF-8");

    println!("cargo:rerun-if-changed={}", icon_str);

    let mut res = winres::WindowsResource::new();
    // winres expects &str, not Cow/path
    res.set_icon(icon_str);

    // Optional file metadata (nice for Explorer “Details”)
    res.set("FileDescription", "HSIP Command Line");
    res.set("ProductName", "HSIP CLI");
    res.set("CompanyName", "Nyx Systems LLC");
    res.set("ProductVersion", "0.2.0.0");
    res.set("FileVersion", "0.2.0.0");

    res.compile().expect("failed to embed Windows icon/metadata");
}

#[cfg(not(windows))]
fn main() {
    // No-op on non-Windows targets
}
