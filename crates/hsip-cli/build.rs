// crates/hsip-cli/build.rs

fn main() {
    // Allow skipping resource embedding (CI or local)
    if std::env::var("HSIP_NO_ICON").ok().as_deref() == Some("1") {
        return;
    }

    // Only attempt on Windows + release builds
    #[cfg(all(windows, not(debug_assertions)))]
    {
        // If embedding fails for any reason, just skip (don’t block the build)
        let _ = try_embed();
    }
}

#[cfg(all(windows, not(debug_assertions)))]
fn try_embed() -> Result<(), Box<dyn std::error::Error>> {
    use std::path::Path;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    // Prefer repo-root/installer/hsip.ico, else fall back to crates/hsip-cli/hsip.ico
    let icon_guess = Path::new(&manifest_dir)
        .join("..").join("..").join("installer").join("hsip.ico");
    let icon_path = if icon_guess.exists() {
        icon_guess
    } else {
        Path::new(&manifest_dir).join("hsip.ico")
    };

    // Ensure we only pass &str to winres
    let icon_str = icon_path
        .to_str()
        .ok_or("icon path is not valid UTF-8")?;

    println!("cargo:rerun-if-changed={}", icon_str);

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_str); // <-- expects &str
    res.set("FileDescription", "HSIP Command Line");
    res.set("ProductName", "HSIP CLI");
    res.set("CompanyName", "Nyx Systems LLC");
    res.set("ProductVersion", "0.2.0.0");
    res.set("FileVersion", "0.2.0.0");
    res.compile()?;
    Ok(())
}
