use openssl::x509::X509;

#[derive(Default)]
pub struct SystemCertificates {
    pub roots: Vec<X509>,
    pub intermediates: Vec<X509>,
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::ptr;

    use openssl::x509::X509;

    use super::SystemCertificates;

    #[repr(C)]
    struct CertContext {
        encoding: u32,
        encoded: *const u8,
        length: u32,
        info: *const c_void,
        store: *mut c_void,
    }

    #[link(name = "Crypt32")]
    unsafe extern "system" {
        fn CertOpenSystemStoreW(provider: *const c_void, store_name: *const u16) -> *mut c_void;
        fn CertEnumCertificatesInStore(store: *mut c_void, previous: *const CertContext) -> *const CertContext;
        fn CertCloseStore(store: *mut c_void, flags: u32) -> i32;
    }

    fn read_store(name: &str) -> Result<Vec<X509>, String> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: The UTF-16 buffer is valid for the call; provider is optional.
        let store = unsafe { CertOpenSystemStoreW(ptr::null(), wide.as_ptr()) };
        if store.is_null() {
            return Err(format!("Unable to open the Windows {name} certificate store"));
        }
        let mut certs = Vec::new();
        let mut previous = ptr::null();
        loop {
            // SAFETY: The previous context is owned by CertEnumCertificatesInStore.
            let current = unsafe { CertEnumCertificatesInStore(store, previous) };
            if current.is_null() { break; }
            // SAFETY: Current is valid until the next enumeration call.
            let der = unsafe {
                std::slice::from_raw_parts((*current).encoded, (*current).length as usize)
            };
            if let Ok(cert) = X509::from_der(der) { certs.push(cert); }
            previous = current;
        }
        // SAFETY: The handle was opened above and is closed exactly once.
        unsafe { CertCloseStore(store, 0); }
        Ok(certs)
    }

    pub fn load() -> Result<SystemCertificates, String> {
        Ok(SystemCertificates {
            roots: read_store("ROOT")?,
            intermediates: read_store("CA")?,
        })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::SystemCertificates;
    pub fn load() -> Result<SystemCertificates, String> {
        Err("Windows system trust is only available on Windows".into())
    }
}

pub fn load() -> Result<SystemCertificates, String> {
    platform::load()
}
