#[cfg(windows)]
fn main() {
    configure_windows_executable();
}

#[cfg(not(windows))]
fn main() {
}

#[cfg(windows)]
fn configure_windows_executable() {
    use std::path::PathBuf;

    // Trigger rebuild when environment changes
    println!("cargo:rerun-if-env-changed=HSIP_NO_ICON");

    // Check if icon embedding is disabled via environment flag
    if icon_embedding_disabled() {
        return;
    }

    let icon_location = locate_icon_file();
    register_rebuild_trigger(&icon_location);
    embed_windows_resources(&icon_location);
}

#[cfg(windows)]
fn icon_embedding_disabled() -> bool {
    std::env::var("HSIP_NO_ICON")
        .ok()
        .map(|v| v == "1")
        .unwrap_or(false)
}

#[cfg(windows)]
fn locate_icon_file() -> PathBuf {
    use std::path::PathBuf;

    let crate_directory = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR environment variable not set");

    let repository_icon = PathBuf::from(&crate_directory)
        .join("..")
        .join("..")
        .join("installer")
        .join("hsip.ico");

    if repository_icon.exists() {
        return repository_icon;
    }

    // Fallback to crate-local icon
    PathBuf::from(&crate_directory).join("hsip.ico")
}

#[cfg(windows)]
fn register_rebuild_trigger(icon_path: &std::path::Path) {
    let path_string = icon_path
        .to_str()
        .expect("Icon path contains invalid UTF-8");
    println!("cargo:rerun-if-changed={}", path_string);
}

#[cfg(windows)]
fn embed_windows_resources(icon_path: &std::path::Path) {
    let mut resource_builder = winres::WindowsResource::new();

    let icon_string = icon_path
        .to_str()
        .expect("Icon path is not valid UTF-8");

    resource_builder.set_icon(icon_string);

    // Application metadata for Windows Explorer
    resource_builder.set("FileDescription", "HSIP Command Line");
    resource_builder.set("ProductName", "HSIP CLI");
    resource_builder.set("CompanyName", "Nyx Systems LLC");
    resource_builder.set("ProductVersion", "0.2.0.0");
    resource_builder.set("FileVersion", "0.2.0.0");

    resource_builder
        .compile()
        .expect("Failed to compile Windows resources");
}
