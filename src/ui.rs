use eframe::egui::{self, Color32, RichText, TextStyle};
use serde_json::Value;

pub fn color_for_origin(origin: Option<&str>, dark: bool) -> Color32 {
    match origin {
        Some("system") if dark => Color32::from_rgb(134, 197, 255),
        Some("system") => Color32::from_rgb(33, 106, 171),
        Some("database") if dark => Color32::from_rgb(210, 168, 255),
        Some("database") => Color32::from_rgb(119, 70, 173),
        _ => {
            if dark { Color32::from_rgb(230, 235, 240) }
            else { Color32::from_rgb(35, 40, 45) }
        }
    }
}

fn json_color(value: &Value, dark: bool) -> Color32 {
    let (light, dark_color) = match value {
        Value::String(_) => ((25, 123, 67), (168, 214, 163)),
        Value::Number(_) => ((172, 88, 26), (255, 191, 124)),
        Value::Bool(_) | Value::Null => ((136, 54, 169), (219, 173, 255)),
        Value::Object(_) | Value::Array(_) => ((111, 123, 137), (146, 156, 170)),
    };
    let (r, g, b) = if dark { dark_color } else { light };
    Color32::from_rgb(r, g, b)
}

fn summary(value: &Value) -> String {
    match value {
        Value::Object(items) => format!("{{{} fields}}", items.len()),
        Value::Array(items) => format!("[{} items]", items.len()),
        Value::String(string) => string.clone(),
        _ => value.to_string(),
    }
}

fn draw_value(
    ui: &mut egui::Ui, key: &str, value: &Value,
    dark: bool, selected: &mut Option<(String, Value)>,
    depth: usize,
) {
    if depth > 64 { ui.label("Maximum tree depth reached"); return; }
    let composite = matches!(value, Value::Object(_) | Value::Array(_));
    let label = summary(value);
    let value_text = if label.chars().count() > 160 {
        format!("{}...", label.chars().take(157).collect::<String>())
    } else { label };
    let field_color = if dark { Color32::from_rgb(170, 181, 194) }
        else { Color32::from_rgb(92, 104, 119) };
    let value_color = json_color(value, dark);

    let mut draw_label = |ui: &mut egui::Ui| {
        let response = ui.horizontal(|ui| {
            ui.add(egui::Label::new(RichText::new(key).color(field_color)).selectable(true));
            let styled = RichText::new(&value_text).color(value_color).monospace();
            let styled = if composite { styled.italics() } else { styled };
            ui.add(egui::Label::new(styled).selectable(true));
        }).response;
        response.context_menu(|ui| {
            if ui.button("Copy field").clicked() { ui.ctx().copy_text(key.to_owned()); ui.close_menu(); }
            if ui.button("Copy value").clicked() {
                let text = match value {
                    Value::String(s) => s.clone(),
                    _ => serde_json::to_string_pretty(value).unwrap_or_default(),
                };
                ui.ctx().copy_text(text);
                ui.close_menu();
            }
            if ui.button("Copy element").clicked() {
                let text = serde_json::to_string_pretty(&serde_json::json!({key:value}))
                    .unwrap_or_default();
                ui.ctx().copy_text(text);
                ui.close_menu();
            }
        });
        if response.clicked() {
            *selected = Some((key.to_owned(), value.clone()));
        }
    };
    match value {
        Value::Object(items) => {
            egui::CollapsingHeader::new(format!("{key}   {value_text}"))
                .id_salt((depth, key))
                .show(ui, |ui| {
                    for (field, child) in items {
                        draw_value(ui, field, child, dark, selected, depth + 1);
                    }
                });
        }
        Value::Array(items) => {
            egui::CollapsingHeader::new(format!("{key}   {value_text}"))
                .id_salt((depth, key))
                .show(ui, |ui| {
                    for (index, child) in items.iter().enumerate() {
                        draw_value(ui, &format!("[{index}]"), child, dark, selected, depth + 1);
                    }
                });
        }
        _ => draw_label(ui),
    }
}

pub fn json_tree(ui: &mut egui::Ui, data: &Value, selected: &mut Option<(String, Value)>) {
    let dark = ui.visuals().dark_mode;
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        draw_value(ui, "Result", data, dark, selected, 0);
    });
    let copy = ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::C));
    if copy {
        if let Some((_, value)) = selected {
            let text = value.as_str().map(ToOwned::to_owned)
                .unwrap_or_else(|| serde_json::to_string_pretty(value).unwrap_or_default());
            ui.ctx().copy_text(text);
        }
    }
}

pub fn json_text(ui: &mut egui::Ui, data: &Value) {
    let mut json = serde_json::to_string_pretty(data).unwrap_or_default();
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        ui.add(
            egui::TextEdit::multiline(&mut json)
                .font(TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .interactive(false)
                .code_editor()
        );
    });
}

pub fn selected_report_json(report: &tlspect::model::VerificationReport) -> Value {
    serde_json::to_value(report).unwrap_or(Value::Null)
}
