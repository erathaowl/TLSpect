# TLSpect

TLSpect è un programma desktop per Windows scritto in Rust per ispezionare certificati X.509 e verificare catene TLS. Riprende le funzionalità di [CertScope](https://github.com/erathaowl/CertScope/tree/v1.2.1).

**Stato:** prima implementazione Rust. Sono ancora in corso compilazione Windows e verifica della compatibilità funzionale.

L'interfaccia dispone di due editor PEM, rispettivamente per i certificati e per la CA personalizzata. È possibile importare file, incollare PEM, esportare il contenuto e salvare certificati/CA con nome nel database SQLite. Dal campo URL si recupera la chain presentata da un server HTTPS/TLS, compresi certificati non attendibili.

La verifica utilizza tre fonti separate, nell'ordine: CA di sistema Windows, CA attendibili e abilitate in SQLite, CA temporanea. Sono disponibili modalità Generic, TLS server e TLS client, verifica hostname/IP, diagnostica OpenSSL, albero dei certificati, output JSON e PEM.

La gestione degli elementi salvati permette di abilitarli, disabilitarli, marcarli attendibili, rinominarli ed eliminarli. È prevista l'importazione esplicita dal database CertScope.

## Compilazione

Installare Rust stable e i Build Tools MSVC su Windows 10 o 11. Per OpenSSL vendored servono Perl e un compilatore C.

    cargo build --release --target x86_64-pc-windows-msvc

Il file generato è target/x86_64-pc-windows-msvc/release/tlspect.exe, senza console e senza dipendenze runtime Python.

## Database e sicurezza

Il database si trova in %LOCALAPPDATA%/TLSpect/tlspect.sqlite3. I certificati letti in input non diventano mai CA attendibili automaticamente. Il recupero TLS senza verifica è utilizzato solo per ottenere i certificati.

TLSpect usa OpenSSL con le CA esportate dal sistema Windows, quindi non riproduce tutte le policy CryptoAPI. CRL e OCSP non sono controllati e il report indica chiaramente che la revoca non viene verificata.

## Pubblicazione

I tag vX.Y.Z attivano test, build e pubblicazione di tlspect-windows.zip (con tlspect.exe) e dell'archivio ZIP del codice sorgente al tag.

Licenza MIT; repository: https://github.com/erathaowl/TLSpect

Il font JetBrains Mono Nerd Font Mono è incluso nell'eseguibile con licenza SIL Open Font License (assets/OFL.txt).
