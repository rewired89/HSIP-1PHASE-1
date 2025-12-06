#[cfg(all(windows, not(debug_assertions)))]
fn main() {
    compile_windows_resources();
}

// Skip resource embedding for debug builds and non-Windows platforms
#[cfg(any(not(windows), debug_assertions))]
fn main() {
}

#[cfg(all(windows, not(debug_assertions)))]
fn compile_windows_resources() {
    let mut resource_config = winres::WindowsResource::new();
    
    // Configure application icon
    resource_config.set_icon("installer/hsip.ico");
    
    // Set executable metadata
    resource_config.set("FileDescription", "HSIP Command Line");
    resource_config.set("ProductName", "HSIP CLI");
    resource_config.set("CompanyName", "Nyx Systems LLC");
    resource_config.set("LegalCopyright", "© 2025 Nyx Systems LLC");
    resource_config.set("ProductVersion", "0.2.0.0");
    resource_config.set("FileVersion", "0.2.0.0");
    
    resource_config
        .compile()
        .expect("Windows resource compilation failed");
}
