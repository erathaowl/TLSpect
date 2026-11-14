# TLSpect

TLSpect is a Windows desktop application for inspecting X.509 certificates and their trust chains. It is a Rust rewrite of [CertScope](https://github.com/erathaowl/CertScope/tree/v1.2.1).

**Development status:** Initial Rust implementation; Windows build and behavioral parity tests are in progress.

## Application

The GUI provides two PEM editors for a certificate chain and temporary CA. Paste, open, save to file, or save as a named item in a SQLite database. A URL toolbar can acquire the chain of a remote HTTPS/TLS server even when the peer is untrusted.

Select **Generic**, **TLS server**, or **TLS client** verification. The verification engine tries isolated sources in order: Windows ROOT/CA certificates, explicitly trusted and enabled local SQLite CAs, and finally the temporary CA input. All certificate input is treated as untrusted path material. For failed checks, the GUI presents error codes, depths, hints, validated path, selected trust anchor, certificate details and raw PEM. Structured results have Tree and JSON modes.

The saved-items manager supports loading, renaming, enabling, trusting and removing local certificates, and importing the old CertScope database. Settings store theme, font size, and the Tree/JSON preference.

TLSpect accepts one optional startup argument: the path of a certificate file, a TLS/HTTPS target, or a quoted PEM certificate.

## Build

Use current stable Rust with MSVC build tools on Windows 10 or Windows 11. A Windows x64 machine with Perl and a C compiler is required for vendored OpenSSL.

    cargo build --release --target x86_64-pc-windows-msvc

The release executable is target/x86_64-pc-windows-msvc/release/tlspect.exe. It does not open a console window. SQLite and OpenSSL are built into the application.

## Data and verification

The database is located at %LOCALAPPDATA%/TLSpect/tlspect.sqlite3. It uses the same entries/preferences SQLite schema as CertScope, but a separate default directory. Importing an old database is explicitly requested through the GUI.

TLSpect reads Windows ROOT and CA material, then verifies chains with OpenSSL. This reproduces certificate-list trust decisions but does not implement every Windows CryptoAPI chain policy or disallowed-store restriction. The application does not download certificate revocation lists, OCSP responses or missing intermediates. The report explicitly records revocation as **not checked**.

When fetching a remote certificate, peer validation is disabled only for acquisition. The handshake result is never considered evidence of trust. The acquired chain is subsequently analyzed through the normal verification sources.

## Releases

A push of a semver tag vX.Y.Z builds and tests the Windows application, then publishes:
- tlspect-windows.zip, containing tlspect.exe
- TLSpect-vX.Y.Z-source.zip, containing the matching Git tag

This is a GUI-only Rust project: no CLI executable or Python wheel.

## Credits

TLSpect is released under the MIT license, Copyright (c) 2026 erathaowl. The application's JetBrains Mono Nerd Font Mono is embedded in the executable under the SIL Open Font License (assets/OFL.txt).

Project repository: https://github.com/erathaowl/TLSpect
