fn main() {
    println!("cargo:rerun-if-changed=assets/tlspect.ico");
    println!("cargo:rerun-if-changed=Cargo.toml");
    #[cfg(target_os = "windows")]
    {
        let version = env!("CARGO_PKG_VERSION");
        let resource = winres::WindowsResource::new();
        let mut resource = resource;
        resource.set_icon("assets/tlspect.ico");
        resource.set("ProductName", "TLSpect");
        resource.set("FileDescription", "TLSpect - X.509 Certificate Inspector");
        resource.set("CompanyName", "erathaowl");
        resource.set("LegalCopyright", "Copyright (c) 2026 erathaowl. MIT License.");
        resource.set("Comments", "MIT License | https://github.com/erathaowl/TLSpect");
        resource.set("InternalName", "tlspect");
        resource.set("OriginalFilename", "tlspect.exe");
        resource.set("FileVersion", version);
        resource.set("ProductVersion", version);
        resource.compile().expect("Windows resource compilation failed");
    }
}
