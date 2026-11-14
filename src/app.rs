use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use eframe::egui::{self, Color32, RichText};
use serde_json::{json, Value};

use tlspect::input::{leaf_candidates, parse_pem, read_cert_file};
use tlspect::model::{CertificateDetails, VerificationReport};
use tlspect::remote::{fetch_certificate, RemoteCertificate};
use tlspect::storage::{Entry, Storage};
use tlspect::verify::verify_bundle;

use crate::ui;

const URL: &str = "https://github.com/erathaowl/TLSpect";

#[derive(Clone, Copy, PartialEq, Eq)]
enum PanelTab { Details, VerifiedPath, Diagnostics, RawPem }
#[derive(Clone, Copy, PartialEq, Eq)]
enum DisplayMode { Tree, Json }

enum Event {
    Verified(Result<VerificationReport, String>),
    Fetched(Result<RemoteCertificate, String>),
}

pub struct TlspectApp {
    storage: Option<Storage>,
    input_pem: String,
    custom_ca: String,
    target: String,
    hostname: String,
    purpose: usize,
    report: Option<VerificationReport>,
    selected_cert: Option<(bool, usize)>,
    selected_json: Option<(String, Value)>,
    tab: PanelTab,
    mode: DisplayMode,
    status: String,
    busy: bool,
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    show_about: bool,
    show_settings: bool,
    show_saved: bool,
    show_save: bool,
    save_name: String,
    save_target: usize,
    save_trusted: bool,
    save_replace: bool,
    rename_entry: Option<i64>,
    rename_value: String,
    theme: usize,
    font_size: f32,
    leaf_selection: Vec<(String, String)>,
    last_error: Option<String>,
}

impl TlspectApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Option<String>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "JetBrains Mono Nerd Font".into(),
            egui::FontData::from_static(
                include_bytes!("../assets/JetBrainsMonoNerdFontMono-Regular.ttf")
            ).into(),
        );
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            family.insert(0, "JetBrains Mono Nerd Font".into());
        }
        cc.egui_ctx.set_fonts(fonts);
        let (sender, receiver) = mpsc::channel();
        let opened = Storage::open_default();
        let last_error = opened.as_ref().err().cloned();
        let storage = opened.ok();
        let preference = |key: &str, default: &str| {
            storage.as_ref().map(|db| db.get_preference(key, default))
                .unwrap_or_else(|| default.to_owned())
        };
        let theme = match preference("theme", "system").as_str() {
            "light" => 1, "dark" => 2, _ => 0
        };
        let mode = if preference("result_mode", "Tree") == "JSON" {
            DisplayMode::Json
        } else { DisplayMode::Tree };
        let font_size = preference("font_size", "12").parse().unwrap_or(12.0);
        let mut app = Self {
            storage, input_pem: String::new(), custom_ca: String::new(), target: String::new(),
            hostname: String::new(), purpose: 0, report: None, selected_cert: None,
            selected_json: None, tab: PanelTab::Details, mode, status: "Ready".into(),
            busy: false, sender, receiver,
            show_about: false, show_settings: false, show_saved: false, show_save: false,
            save_name: String::new(), save_target: 0, save_trusted: false, save_replace: false,
            rename_entry: None, rename_value: String::new(), theme, font_size,
            leaf_selection: Vec::new(), last_error,
        };
        app.apply_theme(&cc.egui_ctx);
        if let Some(input) = initial {
            app.load_argument(&input, &cc.egui_ctx);
        }
        app
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        let dark = match self.theme {
            1 => false, 2 => true,
            _ => ctx.system_theme().unwrap_or(egui::Theme::Dark) == egui::Theme::Dark,
        };
        ctx.set_visuals(if dark { egui::Visuals::dark() } else { egui::Visuals::light() });
        ctx.set_pixels_per_point((self.font_size / 12.0).clamp(0.75, 1.8));
    }

    fn save_preferences(&self) {
        if let Some(storage) = &self.storage {
            let _ = storage.set_preference("theme", ["system", "light", "dark"][self.theme]);
            let _ = storage.set_preference("font_size", &self.font_size.to_string());
            let _ = storage.set_preference(
                "result_mode", if self.mode == DisplayMode::Tree { "Tree" } else { "JSON" }
            );
        }
    }

    fn error(&mut self, text: impl Into<String>) {
        let error = text.into();
        self.status = format!("Error: {error}");
        self.last_error = Some(error);
    }

    fn load_argument(&mut self, argument: &str, ctx: &egui::Context) {
        let path = PathBuf::from(argument);
        if path.is_file() {
            match read_cert_file(&path) {
                Ok(pem) => { self.input_pem = pem; self.launch_analysis(ctx, None); }
                Err(error) => self.error(error),
            }
        } else if argument.contains("-----BEGIN CERTIFICATE-----") {
            self.input_pem = argument.to_owned();
            self.launch_analysis(ctx, None);
        } else {
            self.target = argument.to_owned();
            self.launch_fetch(ctx);
        }
    }

    fn launch_fetch(&mut self, ctx: &egui::Context) {
        if self.busy { return; }
        self.busy = true;
        self.report = None;
        self.status = format!("Connecting to {}...", self.target);
        self.last_error = None;
        let sender = self.sender.clone();
        let context = ctx.clone();
        let target = self.target.clone();
        std::thread::spawn(move || {
            let result = fetch_certificate(&target, Duration::from_secs(8));
            let _ = sender.send(Event::Fetched(result));
            context.request_repaint();
        });
    }

    fn launch_analysis(&mut self, ctx: &egui::Context, leaf: Option<String>) {
        if self.busy { return; }
        let Some(db) = self.storage.clone() else {
            self.error("Unable to open the TLSpect database");
            return;
        };
        if self.purpose == 1 && self.hostname.trim().is_empty() {
            self.error("TLS server verification requires a hostname or IP address");
            return;
        }
        let parsed = match parse_pem(&self.input_pem) {
            Ok(items) => items,
            Err(error) => { self.error(error); return; }
        };
        let candidates = leaf_candidates(&parsed);
        if leaf.is_none() && candidates.len() > 1 {
            self.leaf_selection = candidates.iter()
                .map(|item| (item.fingerprint.clone(),
                    item.cert.subject_name().entries().next()
                        .map(|x| x.data().to_string()).unwrap_or(item.fingerprint.clone())
                )).collect();
            return;
        }
        self.busy = true;
        self.report = None;
        self.selected_cert = None;
        self.last_error = None;
        self.status = "Verifying certificate chain...".into();
        let sender = self.sender.clone();
        let context = ctx.clone();
        let input = self.input_pem.clone();
        let custom = self.custom_ca.clone();
        let hostname = self.hostname.trim().to_owned();
        let purpose = ["generic", "tls-server", "tls-client"][self.purpose].to_owned();
        std::thread::spawn(move || {
            let result = verify_bundle(
                &input, &db, &custom, &purpose,
                if hostname.is_empty() { None } else { Some(&hostname) },
                leaf.as_deref(),
            );
            let _ = sender.send(Event::Verified(result));
            context.request_repaint();
        });
    }

    fn collect_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.receiver.try_recv() {
            self.busy = false;
            match event {
                Event::Fetched(Ok(remote)) => {
                    self.input_pem = remote.pem;
                    self.hostname = remote.hostname;
                    self.purpose = 1;
                    self.status = format!("Retrieved certificate chain from {}:{}", remote.url, remote.port);
                    self.launch_analysis(ctx, None);
                }
                Event::Fetched(Err(error)) => self.error(error),
                Event::Verified(Ok(report)) => {
                    self.status = format!(
                        "{} | Chain: {} | Trust source: {} | Revocation: not checked",
                        report.status.to_uppercase(), report.chain_status,
                        report.trust_source.as_deref().unwrap_or("none")
                    );
                    self.selected_cert = Some((false, 0));
                    self.report = Some(report);
                    self.tab = PanelTab::Diagnostics;
                }
                Event::Verified(Err(error)) => self.error(error),
            }
        }
    }

    fn save_file(&mut self, custom: bool) {
        let default = if custom { "custom-ca.pem" } else { "certificate.pem" };
        if let Some(path) = rfd::FileDialog::new().set_file_name(default).save_file() {
            let text = if custom { &self.custom_ca } else { &self.input_pem };
            match std::fs::write(&path, text) {
                Ok(()) => self.status = format!("Saved {}", path.display()),
                Err(error) => self.error(error.to_string()),
            }
        }
    }

    fn open_file(&mut self, custom: bool) {
        if let Some(path) = rfd::FileDialog::new().add_filter("Certificates", &["pem", "crt", "cer", "der"]).pick_file() {
            match read_cert_file(&path) {
                Ok(pem) => {
                    if custom { self.custom_ca = pem; } else { self.input_pem = pem; }
                    self.status = format!("Loaded {}", path.display());
                }
                Err(error) => self.error(error),
            }
        }
    }

    fn selected_details(&self) -> Option<&CertificateDetails> {
        let report = self.report.as_ref()?;
        let (verified, index) = self.selected_cert?;
        if verified { report.verified_chain.get(index) } else { report.certificates.get(index) }
    }

    fn report_value(&self) -> Value {
        let Some(report) = &self.report else {
            return json!({"status":"idle", "message":"Analyze a certificate to see results"});
        };
        match self.tab {
            PanelTab::Diagnostics => ui::selected_report_json(report),
            PanelTab::VerifiedPath => json!({
                "source": report.trust_source,
                "trust_anchor": report.trust_anchor,
                "verified_chain": report.verified_chain
            }),
            PanelTab::Details => self.selected_details().map(|cert| {
                let mut result = serde_json::to_value(cert).unwrap_or(Value::Null);
                if let Value::Object(ref mut fields) = result { fields.remove("pem"); }
                result
            }).unwrap_or_else(|| json!({"message":"Select a certificate"})),
            PanelTab::RawPem => Value::Null,
        }
    }

    fn editor(ui: &mut egui::Ui, label: &str, text: &mut String) {
        ui.strong(label);
        egui::ScrollArea::vertical().id_salt(label).auto_shrink([false, false]).show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(11)
                    .code_editor()
            );
        });
    }

    fn editor_toolbar(&mut self, ui: &mut egui::Ui, custom: bool) {
        ui.horizontal_wrapped(|ui| {
            if ui.small_button("Open file").clicked() { self.open_file(custom); }
            if ui.small_button("Save as").clicked() { self.save_file(custom); }
            if ui.small_button("Save named").clicked() {
                self.show_save = true;
                self.save_name.clear();
                self.save_target = usize::from(custom);
                self.save_trusted = false;
            }
            if ui.small_button("Clear").clicked() {
                if custom { self.custom_ca.clear(); } else { self.input_pem.clear(); }
            }
        });
    }

    fn report_tree(&mut self, ui: &mut egui::Ui) {
        let Some(report) = &self.report else {
            ui.label("No certificates analyzed");
            return;
        };
        let mut selected = self.selected_cert;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::CollapsingHeader::new("Provided certificates")
                .default_open(true).show(ui, |ui| {
                    for (i, item) in report.certificates.iter().enumerate() {
                        if ui.selectable_label(selected == Some((false, i)), &item.subject).clicked() {
                            selected = Some((false, i));
                        }
                    }
                });
            egui::CollapsingHeader::new("Verified chain")
                .default_open(true).show(ui, |ui| {
                    for (i, item) in report.verified_chain.iter().enumerate() {
                        let saved = item.saved_name.as_ref()
                            .map(|name| format!("[{name}] ")).unwrap_or_default();
                        let anchor = if i + 1 == report.verified_chain.len() { " [trust anchor]" } else { "" };
                        let label = format!("{saved}{}{anchor}", item.subject);
                        let color = ui::color_for_origin(item.origin.as_deref(), ui.visuals().dark_mode);
                        if ui.selectable_label(
                            selected == Some((true, i)), RichText::new(label).color(color)
                        ).clicked() {
                            selected = Some((true, i));
                        }
                    }
                });
        });
        if self.selected_cert != selected {
            self.selected_cert = selected;
            self.tab = PanelTab::Details;
        }
    }

    fn top_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TLSpect");
                ui.separator();
                ui.label("HTTPS / TLS:");
                ui.add(egui::TextEdit::singleline(&mut self.target).desired_width(370.0)
                    .hint_text("https://example.com:443"));
                if ui.add_enabled(!self.busy, egui::Button::new("Fetch and analyze")).clicked() {
                    self.launch_fetch(ctx);
                }
                ui.separator();
                if ui.button("Saved items").clicked() { self.show_saved = true; }
                if ui.button("Settings").clicked() { self.show_settings = true; }
                if ui.button("About").clicked() { self.show_about = true; }
            });
        });

        egui::TopBottomPanel::top("inputs")
            .resizable(true).default_height(255.0).min_height(145.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Purpose:");
                    egui::ComboBox::from_id_salt("purpose")
                        .selected_text(["Generic", "TLS server", "TLS client"][self.purpose])
                        .show_ui(ui, |ui| {
                            for (i, text) in ["Generic", "TLS server", "TLS client"].iter().enumerate() {
                                ui.selectable_value(&mut self.purpose, i, *text);
                            }
                        });
                    if self.purpose == 1 {
                        ui.label("Hostname / IP:");
                        ui.add(egui::TextEdit::singleline(&mut self.hostname).desired_width(200.0));
                    }
                    if ui.add_enabled(!self.busy, egui::Button::new("Analyze and verify")).clicked() {
                        self.launch_analysis(ctx, None);
                    }
                    if self.busy { ui.spinner(); }
                });
                ui.separator();
                ui.columns(2, |columns| {
                    columns[0].vertical(|ui| {
                        self.editor_toolbar(ui, false);
                        Self::editor(ui, "Certificate / chain (PEM)", &mut self.input_pem);
                    });
                    columns[1].vertical(|ui| {
                        self.editor_toolbar(ui, true);
                        Self::editor(ui, "Temporary custom CA (PEM)", &mut self.custom_ca);
                    });
                });
            });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if let Some(report) = &self.report {
                    let valid = report.status == "trusted";
                    ui.colored_label(
                        if valid { Color32::from_rgb(40, 176, 101) }
                        else { Color32::from_rgb(214, 65, 69) },
                        RichText::new("●").size(20.0),
                    );
                }
                ui.label(&self.status);
            });
        });
    }

    fn output_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::SidePanel::left("certificate_tree").resizable(true).default_width(300.0)
                .min_width(160.0).show_inside(ui, |ui| {
                    ui.strong("Certificates");
                    ui.separator();
                    self.report_tree(ui);
                });
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (PanelTab::Details, "Details"), (PanelTab::VerifiedPath, "Verified path"),
                    (PanelTab::Diagnostics, "Diagnostics"), (PanelTab::RawPem, "Raw PEM"),
                ] {
                    if ui.selectable_label(self.tab == tab, label).clicked() {
                        self.tab = tab;
                    }
                }
                ui.separator();
                if ui.selectable_label(self.mode == DisplayMode::Tree, "Tree").clicked() {
                    self.mode = DisplayMode::Tree;
                    self.save_preferences();
                }
                if ui.selectable_label(self.mode == DisplayMode::Json, "JSON").clicked() {
                    self.mode = DisplayMode::Json;
                    self.save_preferences();
                }
                if ui.button("Copy report").clicked() {
                    if let Some(report) = &self.report {
                        if let Ok(text) = serde_json::to_string_pretty(report) { ctx.copy_text(text); }
                    }
                }
                if ui.button("Export report").clicked() {
                    if let Some(report) = &self.report {
                        if let Some(path) = rfd::FileDialog::new()
                            .set_file_name("report.json").save_file()
                        {
                            match serde_json::to_string_pretty(report) {
                                Ok(text) => {
                                    if let Err(error) = std::fs::write(path, format!("{text}\n")) {
                                        self.error(error.to_string());
                                    }
                                }
                                Err(error) => self.error(error.to_string()),
                            }
                        }
                    }
                }
            });
            ui.separator();
            if self.tab == PanelTab::RawPem {
                let mut pem = self.selected_details().map(|x| x.pem.clone()).unwrap_or_default();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut pem).font(egui::TextStyle::Monospace)
                        .interactive(false).desired_width(f32::INFINITY).code_editor());
                });
            } else {
                let value = self.report_value();
                match self.mode {
                    DisplayMode::Tree => ui::json_tree(ui, &value, &mut self.selected_json),
                    DisplayMode::Json => ui::json_text(ui, &value),
                }
            }
        });
    }

    fn show_settings(&mut self, ctx: &egui::Context) {
        if !self.show_settings { return; }
        let mut open = self.show_settings;
        let mut changed = false;
        egui::Window::new("Settings").open(&mut open).collapsible(false)
            .resizable(false).default_width(380.0).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Appearance");
                    egui::ComboBox::from_id_salt("theme")
                        .selected_text(["System (auto)", "Light", "Dark"][self.theme])
                        .show_ui(ui, |ui| {
                            for (i, name) in ["System (auto)", "Light", "Dark"].iter().enumerate() {
                                if ui.selectable_value(&mut self.theme, i, *name).clicked() { changed = true; }
                            }
                        });
                });
                ui.horizontal(|ui| {
                    ui.label("Font size:");
                    if ui.add(egui::Slider::new(&mut self.font_size, 9.0..=24.0)).changed() {
                        changed = true;
                    }
                });
                ui.label("Editor font: JetBrains Mono Nerd Font Mono");
                ui.separator();
                if ui.button("Open database folder").clicked() {
                    if let Some(db) = &self.storage {
                        if let Some(folder) = db.path.parent() {
                            #[cfg(windows)]
                            { let _ = std::process::Command::new("explorer.exe").arg(folder).spawn(); }
                            #[cfg(not(windows))]
                            { self.status = format!("Database directory: {}", folder.display()); }
                        }
                    }
                }
            });
        self.show_settings = open;
        if changed {
            self.apply_theme(ctx);
            self.save_preferences();
        }
    }

    fn show_about(&mut self, ctx: &egui::Context) {
        if !self.show_about { return; }
        let mut open = self.show_about;
        let mut close = false;
        egui::Window::new("About TLSpect").open(&mut open).collapsible(false)
            .resizable(false).default_width(360.0).show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!("../assets/tlspect.png"))
                            .fit_to_exact_size(egui::vec2(88.0, 88.0))
                    );
                    ui.add_space(6.0);
                    ui.strong(format!("TLSpect - {} (MIT)", env!("CARGO_PKG_VERSION")));
                    ui.hyperlink_to(URL, URL);
                    ui.add_space(8.0);
                    if ui.button("Close").clicked() { close = true; }
                });
            });
        self.show_about = open && !close;
    }

    fn show_save(&mut self, ctx: &egui::Context) {
        if !self.show_save { return; }
        let mut open = self.show_save;
        let mut save = false;
        egui::Window::new("Save named certificate").open(&mut open)
            .collapsible(false).resizable(false).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.text_edit_singleline(&mut self.save_name);
                });
                ui.checkbox(&mut self.save_trusted, "Trusted CA");
                ui.checkbox(&mut self.save_replace, "Replace existing name");
                if ui.button("Save").clicked() { save = true; }
            });
        if save {
            let kind = if self.save_target == 1 || self.save_trusted { "ca" } else { "certificate" };
            let pem = if self.save_target == 1 { &self.custom_ca } else { &self.input_pem };
            let result = self.storage.as_ref().ok_or_else(|| "Database unavailable".to_owned())
                .and_then(|db| db.save(
                    kind, &self.save_name, pem, self.save_trusted, true, self.save_replace
                ));
            match result {
                Ok(()) => { self.status = format!("Saved {kind}: {}", self.save_name); open = false; }
                Err(error) => self.error(error),
            }
        }
        self.show_save = open;
    }

    fn saved_items(&mut self, ctx: &egui::Context) {
        if !self.show_saved { return; }
        let mut open = self.show_saved;
        let items = self.storage.as_ref().and_then(|db| db.list().ok()).unwrap_or_default();
        let mut action: Option<(String, Entry)> = None;
        egui::Window::new("Saved certificates and CAs").open(&mut open)
            .default_size([740.0, 420.0]).show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.strong("Type");
                    ui.add_space(72.0);
                    ui.strong("Name");
                    ui.add_space(160.0);
                    ui.strong("Trusted");
                    ui.add_space(12.0);
                    ui.strong("Enabled");
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for entry in &items {
                        ui.horizontal(|ui| {
                            ui.label(&entry.kind);
                            ui.add_sized([200.0, 20.0], egui::Label::new(&entry.name));
                            ui.colored_label(
                                if entry.trusted { Color32::from_rgb(40, 176, 101) }
                                else { Color32::from_rgb(210, 56, 65) },
                                if entry.trusted { "✓" } else { "✗" }
                            );
                            ui.label(if entry.enabled { "Yes" } else { "No" });
                            if ui.small_button("Load").clicked() {
                                action = Some(("load".into(), entry.clone()));
                            }
                            if entry.kind == "ca" && ui.small_button(
                                if entry.trusted { "Untrust" } else { "Trust" }
                            ).clicked() { action = Some(("trust".into(), entry.clone())); }
                            if ui.small_button(if entry.enabled { "Disable" } else { "Enable" })
                                .clicked() { action = Some(("enable".into(), entry.clone())); }
                            if ui.small_button("Rename").clicked() {
                                self.rename_entry = Some(entry.id);
                                self.rename_value = entry.name.clone();
                            }
                            if ui.small_button("Delete").clicked() {
                                action = Some(("delete".into(), entry.clone()));
                            }
                        });
                    }
                });
                ui.separator();
                if ui.button("Import legacy CertScope database").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("SQLite", &["sqlite3", "db"]).pick_file()
                    {
                        let result = self.storage.as_ref().ok_or("Database unavailable".to_owned())
                            .and_then(|db| db.import_legacy(&path));
                        match result {
                            Ok(count) => self.status = format!("Imported {count} saved items"),
                            Err(error) => self.error(error),
                        }
                    }
                }
            });
        self.show_saved = open;
        if let Some((operation, entry)) = action {
            let result = match operation.as_str() {
                "load" => {
                    if entry.kind == "ca" { self.custom_ca = entry.pem_bundle; }
                    else { self.input_pem = entry.pem_bundle; }
                    Ok(())
                }
                "trust" => self.storage.as_ref().unwrap().set_trusted(entry.id, !entry.trusted),
                "enable" => self.storage.as_ref().unwrap().set_enabled(entry.id, !entry.enabled),
                "delete" => self.storage.as_ref().unwrap().delete(entry.id),
                _ => Ok(()),
            };
            match result {
                Ok(()) => self.status = format!("{operation}: {}", entry.name),
                Err(error) => self.error(error),
            }
        }
    }

    fn show_rename(&mut self, ctx: &egui::Context) {
        if self.rename_entry.is_none() { return; }
        let mut open = true;
        let mut apply = false;
        egui::Window::new("Rename saved item").open(&mut open)
            .collapsible(false).resizable(false).show(ctx, |ui| {
                ui.text_edit_singleline(&mut self.rename_value);
                if ui.button("Rename").clicked() { apply = true; }
            });
        if apply {
            if let Some(storage) = &self.storage {
                match storage.rename(self.rename_entry.unwrap(), &self.rename_value) {
                    Ok(()) => { self.rename_entry = None; self.status = "Saved item renamed".into(); }
                    Err(error) => self.error(error),
                }
            }
        } else if !open {
            self.rename_entry = None;
        }
    }

    fn select_leaf(&mut self, ctx: &egui::Context) {
        if self.leaf_selection.is_empty() { return; }
        let candidates = self.leaf_selection.clone();
        egui::Window::new("Select certificate to verify")
            .collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label("Multiple independent leaf certificates were found.");
                for (fingerprint, subject) in &candidates {
                    if ui.button(format!("{} [{}]", subject, &fingerprint[..16])).clicked() {
                        self.leaf_selection.clear();
                        self.launch_analysis(ctx, Some(fingerprint.clone()));
                    }
                }
                if ui.button("Cancel").clicked() { self.leaf_selection.clear(); }
            });
    }
}

impl eframe::App for TlspectApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.collect_events(ctx);
        let dropped = ctx.input(|input| input.raw.dropped_files.clone());
        if let Some(file) = dropped.first().and_then(|d| d.path.as_ref()) {
            match read_cert_file(file) {
                Ok(content) => { self.input_pem = content; self.status = format!("Loaded {}", file.display()); }
                Err(error) => self.error(error),
            }
        }
        self.top_panel(ctx);
        self.output_panel(ctx);
        self.show_settings(ctx);
        self.show_about(ctx);
        self.show_save(ctx);
        self.saved_items(ctx);
        self.show_rename(ctx);
        self.select_leaf(ctx);
        if let Some(message) = &self.last_error {
            egui::TopBottomPanel::bottom("error").show(ctx, |ui| {
                ui.colored_label(Color32::from_rgb(212, 64, 70), message);
            });
        }
    }
}
