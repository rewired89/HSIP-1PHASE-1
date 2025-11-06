#[cfg(all(windows, not(debug_assertions)))]
fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("installer/hsip.ico"); // your .ico path
    res.set("FileDescription", "HSIP Command Line");
    res.set("ProductName", "HSIP CLI");
    res.set("CompanyName", "Nyx Systems LLC");
    res.set("LegalCopyright", "© 2025 Nyx Systems LLC");
    res.set("ProductVersion", "0.2.0.0");
    res.set("FileVersion", "0.2.0.0");
    res.compile().expect("winres compile failed");
}

#[cfg(any(not(windows), debug_assertions))]
fn main() {}
