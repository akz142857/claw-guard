use crate::engine::{self, Category, Finding, Severity, Status};
use crate::i18n::{Lang, Tr};
use crate::report::AuditReport;
use eframe::egui;
use std::sync::mpsc;

// ── Messages from scan thread → GUI ────────────────────────────────────

enum ScanMsg {
    Progress { rule_id: String, rule_name: String, current: usize, total: usize },
    Done(Box<AuditReport>),
    /// Async cloud results arrived after initial scan
    CloudUpdate {
        agent_id: Option<String>,
        web_url: Option<String>,
        analysis: Option<crate::llm::AnalysisReport>,
    },
    #[allow(dead_code)]
    Error(String),
}

// ── Apple-style color palette (dark mode) ──────────────────────────────

mod colors {
    use eframe::egui::Color32;

    pub const WINDOW_BG: Color32 = Color32::from_rgb(28, 28, 30);
    pub const SURFACE: Color32 = Color32::from_rgb(44, 44, 46);
    pub const SURFACE_HOVER: Color32 = Color32::from_rgb(58, 58, 60);
    pub const SEPARATOR: Color32 = Color32::from_rgb(72, 72, 74);
    pub const TEXT_PRIMARY: Color32 = Color32::WHITE;
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(142, 142, 147);
    pub const TEXT_TERTIARY: Color32 = Color32::from_rgb(99, 99, 102);

    pub const ACCENT_BLUE: Color32 = Color32::from_rgb(0, 122, 255);
    pub const GREEN: Color32 = Color32::from_rgb(48, 209, 88);
    pub const YELLOW: Color32 = Color32::from_rgb(255, 214, 10);
    pub const ORANGE: Color32 = Color32::from_rgb(255, 159, 10);
    pub const RED: Color32 = Color32::from_rgb(255, 69, 58);
    #[allow(dead_code)]
    pub const PURPLE: Color32 = Color32::from_rgb(191, 90, 242);
}

// ── App state ──────────────────────────────────────────────────────────

enum AppState {
    Idle,
    Scanning,
    Done(Box<AuditReport>),
    Error(String),
}

pub struct ClawGuardApp {
    state: AppState,
    progress_text: String,
    progress_current: usize,
    progress_total: usize,
    rx: Option<mpsc::Receiver<ScanMsg>>,
    no_upload: bool,
    filter_category: Option<Category>,
    /// Cached human-readable timestamp, computed once when report arrives
    friendly_time: String,
    /// Current language
    lang: Lang,
}

impl ClawGuardApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let lang = crate::i18n::detect_system_lang();
        apply_theme(&cc.egui_ctx, lang);
        Self {
            state: AppState::Idle,
            progress_text: String::new(),
            progress_current: 0,
            progress_total: 0,
            rx: None,
            no_upload: false,
            filter_category: None,
            friendly_time: String::new(),
            lang,
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        let tr = Tr::new(self.lang);
        self.state = AppState::Scanning;
        self.progress_text = tr.loading_rules().to_string();
        self.progress_current = 0;
        self.progress_total = 0;
        self.filter_category = None;

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);

        let no_upload = self.no_upload;
        let ctx = ctx.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                run_scan(tx, no_upload, &ctx).await;
            });
        });
    }

    fn poll_messages(&mut self) {
        if let Some(ref rx) = self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    ScanMsg::Progress { rule_id, rule_name, current, total } => {
                        self.progress_text = format!("[{}] {}", rule_id, rule_name);
                        self.progress_current = current;
                        self.progress_total = total;
                    }
                    ScanMsg::Done(report) => {
                        self.friendly_time = chrono::DateTime::parse_from_rfc3339(&report.timestamp)
                            .map(|dt| dt.format("%b %d, %Y  %H:%M").to_string())
                            .unwrap_or_else(|_| report.timestamp.clone());
                        self.state = AppState::Done(report);
                        // Don't drop rx yet — cloud updates may still arrive
                    }
                    ScanMsg::CloudUpdate { agent_id, web_url, analysis } => {
                        if let AppState::Done(ref mut report) = self.state {
                            if agent_id.is_some() { report.agent_id = agent_id; }
                            if web_url.is_some() { report.web_url = web_url; }
                            if analysis.is_some() { report.analysis = analysis; }
                        }
                        self.rx = None;
                        return;
                    }
                    ScanMsg::Error(e) => {
                        self.state = AppState::Error(e);
                        self.rx = None;
                        return;
                    }
                }
            }
        }
    }
}

// ── CJK font loading ──────────────────────────────────────────────────

fn load_cjk_fonts(ctx: &egui::Context) {
    let font_paths: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/System/Library/Fonts/STHeiti Medium.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            "C:\\Windows\\Fonts\\msyh.ttc",      // Microsoft YaHei
            "C:\\Windows\\Fonts\\simsun.ttc",     // SimSun
        ]
    } else {
        &[
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        ]
    };

    for path in font_paths {
        if let Ok(font_data) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "cjk".to_owned(),
                egui::FontData::from_owned(font_data).into(),
            );
            // Add CJK font as fallback for proportional text
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push("cjk".to_owned());
            }
            // Also add as fallback for monospace
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                family.push("cjk".to_owned());
            }
            ctx.set_fonts(fonts);
            return;
        }
    }
}

// ── Theme ──────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context, lang: Lang) {
    if lang == Lang::Zh {
        load_cjk_fonts(ctx);
    }
    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = colors::WINDOW_BG;
    visuals.window_fill = colors::WINDOW_BG;
    visuals.extreme_bg_color = colors::SURFACE;

    visuals.widgets.noninteractive.bg_fill = colors::SURFACE;
    visuals.widgets.noninteractive.fg_stroke.color = colors::TEXT_PRIMARY;
    visuals.widgets.noninteractive.corner_radius = 8.0.into();

    visuals.widgets.inactive.bg_fill = colors::SURFACE;
    visuals.widgets.inactive.fg_stroke.color = colors::TEXT_PRIMARY;
    visuals.widgets.inactive.corner_radius = 8.0.into();

    visuals.widgets.hovered.bg_fill = colors::SURFACE_HOVER;
    visuals.widgets.hovered.fg_stroke.color = colors::TEXT_PRIMARY;
    visuals.widgets.hovered.corner_radius = 8.0.into();

    visuals.widgets.active.bg_fill = colors::ACCENT_BLUE;
    visuals.widgets.active.fg_stroke.color = colors::TEXT_PRIMARY;
    visuals.widgets.active.corner_radius = 8.0.into();

    visuals.selection.bg_fill = colors::ACCENT_BLUE;
    visuals.selection.stroke.color = colors::TEXT_PRIMARY;

    visuals.widgets.noninteractive.bg_stroke.color = colors::SEPARATOR;
    visuals.widgets.inactive.bg_stroke.color = colors::SEPARATOR;

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.window_margin = egui::Margin::same(24);
    style.interaction.selectable_labels = true;
    style.url_in_tooltip = false;
    style.visuals.interact_cursor = Some(egui::CursorIcon::PointingHand);
    ctx.set_style(style);
}

// ── Severity / status color helpers ────────────────────────────────────

fn severity_color(sev: Severity) -> egui::Color32 {
    match sev {
        Severity::Critical => colors::RED,
        Severity::High => colors::ORANGE,
        Severity::Medium => colors::YELLOW,
        Severity::Low => colors::GREEN,
        Severity::Info => colors::TEXT_SECONDARY,
    }
}
fn score_color(score: u8) -> egui::Color32 {
    match score {
        90..=100 => colors::GREEN,
        75..=89 => egui::Color32::from_rgb(132, 204, 22),
        60..=74 => colors::YELLOW,
        40..=59 => colors::ORANGE,
        _ => colors::RED,
    }
}

// ── Circular score gauge (Activity Monitor style) ──────────────────────

fn paint_score_gauge(ui: &mut egui::Ui, score: u8, radius: f32) {
    let desired = egui::vec2(radius * 2.0 + 16.0, radius * 2.0 + 16.0);
    let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
    let center = rect.center();
    let painter = ui.painter();
    let stroke_width = 8.0;

    // Background ring
    painter.circle_stroke(center, radius, egui::Stroke::new(stroke_width, colors::SEPARATOR));

    // Foreground arc
    let color = score_color(score);
    let fraction = score as f32 / 100.0;
    let n_points = 64;
    let start_angle = -std::f32::consts::FRAC_PI_2; // 12 o'clock
    let sweep = fraction * std::f32::consts::TAU;

    if fraction > 0.0 {
        let points: Vec<egui::Pos2> = (0..=n_points)
            .map(|i| {
                let t = i as f32 / n_points as f32;
                let angle = start_angle + t * sweep;
                egui::pos2(
                    center.x + radius * angle.cos(),
                    center.y + radius * angle.sin(),
                )
            })
            .collect();
        painter.add(egui::Shape::line(
            points,
            egui::Stroke::new(stroke_width, color),
        ));
    }

    // Center text: score number
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        format!("{}", score),
        egui::FontId::proportional(32.0),
        color,
    );
}

// ── Blue accent button helper ──────────────────────────────────────────

fn accent_button(ui: &mut egui::Ui, text: &str, width: f32, height: f32) -> egui::Response {
    let btn = egui::Button::new(
        egui::RichText::new(text).size(16.0).color(egui::Color32::WHITE).strong(),
    )
    .fill(colors::ACCENT_BLUE)
    .corner_radius(10.0)
    .min_size(egui::vec2(width, height));
    let resp = ui.add(btn);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

// ── Badge pill helper ──────────────────────────────────────────────────

fn badge(ui: &mut egui::Ui, label: &str, fg: egui::Color32, bg: egui::Color32) {
    egui::Frame::new()
        .fill(bg)
        .corner_radius(6.0)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .color(fg)
                    .strong()
                    .monospace()
                    .size(11.0),
            );
        });
}

// ── Card frame helper ──────────────────────────────────────────────────

fn card_frame() -> egui::Frame {
    egui::Frame::new()
        .fill(colors::SURFACE)
        .corner_radius(12.0)
        .inner_margin(egui::Margin::same(20))
        .shadow(egui::epaint::Shadow {
            offset: [0, 2],
            blur: 6,
            spread: 0,
            color: egui::Color32::from_black_alpha(35),
        })
}

// ── eframe::App implementation ─────────────────────────────────────────

impl eframe::App for ClawGuardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_messages();

        if matches!(self.state, AppState::Scanning) {
            ctx.request_repaint();
        }

        let mut wants_reset = false;
        let tr = Tr::new(self.lang);

        match &self.state {
            AppState::Idle => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.render_idle(ui, ctx, &tr);
                });
            }
            AppState::Scanning => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.render_scanning(ui, &tr);
                });
            }
            AppState::Done(report) => {
                let report = report.as_ref();

                egui::SidePanel::left("sidebar")
                    .exact_width(260.0)
                    .frame(
                        egui::Frame::new()
                            .fill(colors::SURFACE)
                            .inner_margin(egui::Margin::same(20)),
                    )
                    .show(ctx, |ui| {
                        wants_reset = Self::render_sidebar(
                            report, &mut self.filter_category, &mut self.lang, ui, &tr,
                        );
                    });

                egui::CentralPanel::default().show(ctx, |ui| {
                    Self::render_main_panel(report, ui, &self.filter_category, &self.friendly_time, &tr);
                });
            }
            AppState::Error(e) => {
                let e = e.clone();
                egui::CentralPanel::default().show(ctx, |ui| {
                    wants_reset = Self::render_error(&e, ui, &tr);
                });
            }
        }

        if wants_reset {
            self.state = AppState::Idle;
            self.filter_category = None;
        }
    }
}

// ── Render helpers ─────────────────────────────────────────────────────

impl ClawGuardApp {
    // ── Welcome / Idle ──

    fn render_idle(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, tr: &Tr) {
        // Language switcher — top right
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                lang_switcher(ui, &mut self.lang);
            });
        });

        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.18).max(32.0));

            // App icon
            let icon_bytes = include_bytes!("../assets/icon.png");
            let icon_image = egui::ColorImage::from_rgba_unmultiplied(
                [256, 256],
                &image::load_from_memory(icon_bytes).unwrap().into_rgba8(),
            );
            let texture = ui.ctx().load_texture("welcome-icon", icon_image, egui::TextureOptions::LINEAR);
            ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(72.0, 72.0)));
            ui.add_space(16.0);

            // Title
            ui.label(
                egui::RichText::new("ClawGuard")
                    .size(32.0)
                    .strong()
                    .color(colors::TEXT_PRIMARY),
            );
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(tr.app_subtitle())
                    .size(14.0)
                    .color(colors::TEXT_TERTIARY),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .size(11.0)
                    .color(colors::TEXT_TERTIARY),
            );

            ui.add_space(40.0);

            // Cloud toggle — positive framing, centered
            let mut cloud_on = !self.no_upload;
            ui.checkbox(&mut cloud_on, egui::RichText::new(tr.cloud_analysis()).size(13.0).color(colors::TEXT_PRIMARY));
            self.no_upload = !cloud_on;
            ui.label(
                egui::RichText::new(tr.cloud_analysis_desc())
                    .size(11.0)
                    .color(colors::TEXT_TERTIARY),
            );

            ui.add_space(32.0);

            if accent_button(ui, tr.start_scan(), 220.0, 48.0).clicked() {
                self.start_scan(ctx);
            }
        });
    }

    // ── Scanning ──

    fn render_scanning(&self, ui: &mut egui::Ui, tr: &Tr) {
        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.30).max(60.0));

            ui.label(
                egui::RichText::new(tr.scanning())
                    .size(20.0)
                    .color(colors::TEXT_PRIMARY),
            );
            ui.add_space(24.0);

            if self.progress_total > 0 {
                let pct = self.progress_current as f32 / self.progress_total as f32;

                // Custom rounded progress bar
                let desired = egui::vec2(360.0, 12.0);
                let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
                let painter = ui.painter();
                let rounding = 6.0;

                // Track
                painter.rect_filled(rect, rounding, colors::SEPARATOR);
                // Fill
                let fill_rect = egui::Rect::from_min_size(
                    rect.min,
                    egui::vec2(rect.width() * pct, rect.height()),
                );
                painter.rect_filled(fill_rect, rounding, colors::ACCENT_BLUE);

                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("{} / {}", self.progress_current, self.progress_total))
                        .size(13.0)
                        .color(colors::TEXT_SECONDARY),
                );
            }

            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(&self.progress_text)
                    .size(12.0)
                    .color(colors::TEXT_TERTIARY),
            );
        });
    }

    // ── Results: Sidebar ──

    fn render_sidebar(
        report: &AuditReport,
        filter_category: &mut Option<Category>,
        lang: &mut Lang,
        ui: &mut egui::Ui,
        tr: &Tr,
    ) -> bool {
        let mut wants_reset = false;
        let has_agent = report.agent_id.is_some();
        let has_url = report.web_url.is_some();

        let bottom_h = 80.0
            + if has_agent && has_url { 140.0 }
              else if has_agent || has_url { 90.0 }
              else { 0.0 };
        let total_h = ui.available_height();

        // ── Language switcher — top right, minimal ──
        let prev_lang = *lang;
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                for &l in Lang::all().iter().rev() {
                    let selected = *lang == l;
                    let text = egui::RichText::new(l.label()).size(11.0);
                    let text = if selected { text.strong().color(colors::ACCENT_BLUE) } else { text.color(colors::TEXT_TERTIARY) };
                    if ui.add(egui::Button::new(text).fill(egui::Color32::TRANSPARENT).frame(false))
                        .on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                        *lang = l;
                    }
                }
            });
        });
        if *lang == Lang::Zh && prev_lang != Lang::Zh {
            load_cjk_fonts(ui.ctx());
        }
        ui.add_space(8.0);

        // ── Score gauge ──
        ui.vertical_centered(|ui| {
            paint_score_gauge(ui, report.summary.score, 48.0);
        });
        ui.add_space(4.0);
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new(tr.score_label(report.summary.score))
                    .size(13.0)
                    .color(score_color(report.summary.score))
                    .strong(),
            );
        });

        // ── Stats — three equal columns ──
        ui.add_space(12.0);
        let avail_w = ui.available_width();
        let block_w = (avail_w - 16.0) / 3.0; // 8px gap × 2
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            for (count, label) in [
                (report.summary.pass, tr.pass()),
                (report.summary.fail, tr.fail()),
                (report.summary.warn, tr.warn()),
            ] {
                egui::Frame::new()
                    .fill(colors::WINDOW_BG)
                    .corner_radius(8.0)
                    .inner_margin(egui::Margin::symmetric(4, 6))
                    .show(ui, |ui| {
                        ui.set_width(block_w - 12.0);
                        ui.vertical_centered(|ui| {
                            ui.label(
                                egui::RichText::new(format!("{}", count))
                                    .size(16.0)
                                    .strong()
                                    .color(colors::TEXT_PRIMARY),
                            );
                            ui.label(
                                egui::RichText::new(label)
                                    .size(10.0)
                                    .color(colors::TEXT_TERTIARY),
                            );
                        });
                    });
            }
        });

        ui.add_space(16.0);

        // ── Category list ──
        ui.label(
            egui::RichText::new(tr.categories())
                .size(12.0)
                .color(colors::TEXT_TERTIARY),
        );
        ui.add_space(4.0);

        let used_so_far = total_h - ui.available_height();
        let cat_height = (total_h - used_so_far - bottom_h).max(80.0);

        egui::ScrollArea::vertical()
            .max_height(cat_height)
            .show(ui, |ui| {
                let all_selected = filter_category.is_none();
                if ui.selectable_label(all_selected, egui::RichText::new(tr.all_findings()).size(13.0))
                    .on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    *filter_category = None;
                }

                for cat in &report.categories {
                    let is_selected = *filter_category == Some(cat.category);
                    let has_issues = cat.fail > 0 || cat.warn > 0;

                    ui.horizontal(|ui| {
                        let cat_name = tr.category_name(cat.category);
                        let text = egui::RichText::new(cat_name).size(12.0);
                        let text = if is_selected {
                            text.strong().color(colors::TEXT_PRIMARY)
                        } else if has_issues {
                            text.strong()
                        } else {
                            text.color(colors::TEXT_SECONDARY)
                        };
                        if ui.selectable_label(is_selected, text)
                            .on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                            if is_selected { *filter_category = None; }
                            else { *filter_category = Some(cat.category); }
                        }

                        if cat.fail > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(format!("{}", cat.fail)).size(11.0).color(colors::TEXT_SECONDARY).strong());
                            });
                        } else if cat.warn > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(format!("{}", cat.warn)).size(11.0).color(colors::TEXT_TERTIARY));
                            });
                        }
                    });
                }
            });

        // ── Bottom zone: cloud info (prominent) ──
        ui.add_space(8.0);

        if has_agent || has_url {
            egui::Frame::new()
                .fill(colors::WINDOW_BG)
                .corner_radius(10.0)
                .inner_margin(egui::Margin::same(12))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    if let Some(ref id) = report.agent_id {
                        ui.label(
                            egui::RichText::new(tr.agent_id())
                                .size(10.0)
                                .color(colors::TEXT_TERTIARY)
                                .strong(),
                        );
                        ui.add_space(2.0);
                        let resp = ui.add(
                            egui::Button::new(
                                egui::RichText::new(id).size(10.0).monospace().color(colors::TEXT_SECONDARY),
                            ).fill(egui::Color32::TRANSPARENT).frame(false)
                        );
                        if resp.clicked() { ui.ctx().copy_text(id.clone()); }
                        resp.on_hover_cursor(egui::CursorIcon::Copy);
                    }

                    if has_agent && has_url {
                        ui.add_space(8.0);
                    }

                    if let Some(ref url) = report.web_url {
                        let w = ui.available_width();
                        let resp = ui.vertical_centered(|ui| {
                            ui.add(
                                egui::Button::new(
                                    egui::RichText::new(tr.view_web_report())
                                        .size(13.0)
                                        .color(egui::Color32::WHITE)
                                        .strong(),
                                )
                                .fill(colors::ACCENT_BLUE)
                                .corner_radius(8.0)
                                .min_size(egui::vec2(w, 34.0))
                            ).on_hover_cursor(egui::CursorIcon::PointingHand)
                        });
                        if resp.inner.clicked() {
                            #[cfg(target_os = "macos")]
                            { let _ = std::process::Command::new("open").arg(url).spawn(); }
                            #[cfg(target_os = "linux")]
                            { let _ = std::process::Command::new("xdg-open").arg(url).spawn(); }
                            #[cfg(target_os = "windows")]
                            { let _ = std::process::Command::new("cmd").args(["/C", "start", url]).spawn(); }
                        }
                    }
                });
            ui.add_space(8.0);
        }

        ui.vertical_centered(|ui| {
            let btn = egui::Button::new(
                egui::RichText::new(tr.new_scan()).size(13.0).color(colors::TEXT_PRIMARY),
            )
            .fill(colors::SURFACE_HOVER)
            .corner_radius(8.0)
            .min_size(egui::vec2(ui.available_width(), 36.0));
            if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                wants_reset = true;
            }
        });

        wants_reset
    }

    // ── Results: Main panel ──

    fn render_main_panel(
        report: &AuditReport,
        ui: &mut egui::Ui,
        filter_category: &Option<Category>,
        friendly_time: &str,
        tr: &Tr,
    ) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(16.0);

            // Section heading
            let heading_text = match filter_category {
                Some(cat) => tr.category_name(*cat).to_string(),
                None => tr.all_findings().to_string(),
            };
            ui.label(
                egui::RichText::new(&heading_text)
                    .size(20.0)
                    .strong()
                    .color(colors::TEXT_PRIMARY),
            );

            // Subtitle: hostname, OS, time
            ui.label(
                egui::RichText::new(format!("{} — {}  |  {}", report.hostname, report.os, friendly_time))
                    .size(12.0)
                    .color(colors::TEXT_TERTIARY),
            );

            // Subtle separator
            ui.add_space(12.0);
            let rect = ui.available_rect_before_wrap();
            ui.painter().line_segment(
                [egui::pos2(rect.left(), rect.top()), egui::pos2(rect.right(), rect.top())],
                egui::Stroke::new(0.5, colors::SEPARATOR),
            );
            ui.add_space(20.0);

            // ── Finding cards (issues) ──
            let issues: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.status != Status::Pass && f.status != Status::Skip)
                .filter(|f| filter_category.is_none_or(|cat| f.category == cat))
                .collect();

            if issues.is_empty() && filter_category.is_some() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new(tr.no_issues_in_category())
                            .size(14.0)
                            .color(colors::TEXT_TERTIARY),
                    );
                });
            }

            let web_url = report.web_url.as_deref();
            for finding in &issues {
                render_finding_card(ui, finding, tr, web_url);
                ui.add_space(16.0);
            }

            // ── Passed (compact green rows) ──
            let passed: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.status == Status::Pass)
                .filter(|f| filter_category.is_none_or(|cat| f.category == cat))
                .collect();

            if !passed.is_empty() {
                ui.add_space(24.0);
                ui.collapsing(
                    egui::RichText::new(format!("{} ({})", tr.passed(), passed.len()))
                        .size(14.0)
                        .color(colors::TEXT_SECONDARY),
                    |ui| {
                        for f in &passed {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new("\u{2713}")
                                        .color(colors::GREEN)
                                        .size(12.0),
                                );
                                ui.label(
                                    egui::RichText::new(&f.rule_id)
                                        .monospace()
                                        .size(12.0)
                                        .color(colors::TEXT_SECONDARY),
                                );
                                ui.label(
                                    egui::RichText::new(&f.detail)
                                        .size(12.0)
                                        .color(colors::TEXT_SECONDARY),
                                );
                            });
                        }
                    },
                );
            }

            // ── AI Analysis ──
            if let Some(ref analysis) = report.analysis {
                ui.add_space(32.0);
                ui.label(
                    egui::RichText::new(tr.ai_analysis())
                        .size(18.0)
                        .strong()
                        .color(colors::TEXT_PRIMARY),
                );
                ui.add_space(8.0);

                // Executive summary card
                card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width() - 4.0);
                    ui.label(
                        egui::RichText::new(tr.executive_summary())
                            .size(13.0)
                            .strong()
                            .color(colors::TEXT_SECONDARY),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new(&analysis.executive_summary)
                            .size(13.0)
                            .color(colors::TEXT_PRIMARY),
                    );
                });

                // Attack chains
                if !analysis.risk_chains.is_empty() {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new(tr.attack_chains())
                            .size(14.0)
                            .strong()
                            .color(colors::TEXT_PRIMARY),
                    );
                    ui.add_space(4.0);

                    for chain in &analysis.risk_chains {
                        card_frame().show(ui, |ui| {
                            ui.set_width(ui.available_width() - 4.0);
                            ui.horizontal(|ui| {
                                badge(ui, &chain.likelihood, colors::ORANGE, egui::Color32::from_rgb(124, 45, 18));
                                ui.label(
                                    egui::RichText::new(&chain.name)
                                        .size(13.0)
                                        .strong()
                                        .color(colors::TEXT_PRIMARY),
                                );
                            });
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} \u{2192} {}",
                                    chain.finding_ids.join(" + "),
                                    chain.impact,
                                ))
                                .size(12.0)
                                .color(colors::TEXT_SECONDARY),
                            );
                        });
                        ui.add_space(4.0);
                    }
                }

                // Priority fixes
                if !analysis.priority_actions.is_empty() {
                    ui.add_space(12.0);
                    ui.label(
                        egui::RichText::new(tr.priority_fixes())
                            .size(14.0)
                            .strong()
                            .color(colors::TEXT_PRIMARY),
                    );
                    ui.add_space(4.0);

                    card_frame().show(ui, |ui| {
                        ui.set_width(ui.available_width() - 4.0);
                        for action in &analysis.priority_actions {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    egui::RichText::new(format!("{}.", action.priority))
                                        .size(13.0)
                                        .strong()
                                        .color(colors::ACCENT_BLUE),
                                );
                                ui.label(
                                    egui::RichText::new(&action.command)
                                        .size(12.0)
                                        .monospace()
                                        .color(colors::TEXT_PRIMARY),
                                );
                            });
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}: {}",
                                    action.finding_ids.join(", "),
                                    action.reason,
                                ))
                                .size(11.0)
                                .color(colors::TEXT_TERTIARY),
                            );
                            ui.add_space(4.0);
                        }
                    });
                }

                // Context notes
                if !analysis.context_notes.is_empty() {
                    ui.add_space(8.0);
                    ui.collapsing(
                        egui::RichText::new(tr.context_notes())
                            .size(13.0)
                            .color(colors::TEXT_SECONDARY),
                        |ui| {
                            for note in &analysis.context_notes {
                                ui.label(
                                    egui::RichText::new(format!("\u{2022} {}", note))
                                        .size(12.0)
                                        .color(colors::TEXT_SECONDARY),
                                );
                            }
                        },
                    );
                }
            }

            ui.add_space(24.0);
        });
    }

    // ── Error ──

    fn render_error(err_msg: &str, ui: &mut egui::Ui, tr: &Tr) -> bool {
        let mut wants_reset = false;
        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.30).max(60.0));

            ui.label(
                egui::RichText::new(tr.scan_error())
                    .size(24.0)
                    .color(colors::RED),
            );
            ui.add_space(16.0);

            card_frame().show(ui, |ui| {
                ui.set_width(400.0);
                ui.label(
                    egui::RichText::new(err_msg)
                        .size(13.0)
                        .color(colors::TEXT_PRIMARY),
                );
            });

            ui.add_space(20.0);
            if accent_button(ui, tr.back(), 120.0, 36.0).clicked() {
                wants_reset = true;
            }
        });
        wants_reset
    }
}

// ── Language switcher (pill-style toggle) ──────────────────────────────

fn lang_switcher(ui: &mut egui::Ui, current: &mut Lang) {
    let prev = *current;
    for &lang in Lang::all() {
        let selected = *current == lang;
        let (fill, text_color) = if selected {
            (colors::ACCENT_BLUE, egui::Color32::WHITE)
        } else {
            (colors::SURFACE_HOVER, colors::TEXT_SECONDARY)
        };
        let btn = egui::Button::new(
            egui::RichText::new(lang.label())
                .size(12.0)
                .color(text_color)
                .strong(),
        )
        .fill(fill)
        .corner_radius(6.0)
        .min_size(egui::vec2(60.0, 24.0));
        if ui.add(btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            *current = lang;
        }
    }
    // Load CJK fonts on demand when switching to Chinese
    if *current == Lang::Zh && prev != Lang::Zh {
        load_cjk_fonts(ui.ctx());
    }
}

// ── Finding card ───────────────────────────────────────────────────────

fn render_finding_card(ui: &mut egui::Ui, finding: &Finding, tr: &Tr, web_url: Option<&str>) {
    let sev_col = severity_color(finding.severity);

    let frame = egui::Frame::new()
        .fill(colors::SURFACE)
        .corner_radius(12.0)
        .inner_margin(egui::Margin {
            left: 20,
            right: 20,
            top: 16,
            bottom: 16,
        })
        .shadow(egui::epaint::Shadow {
            offset: [0, 1],
            blur: 4,
            spread: 0,
            color: egui::Color32::from_black_alpha(25),
        });

    let resp = frame.show(ui, |ui| {
        ui.set_width(ui.available_width() - 4.0);

        // Row 1: severity badge + rule ID (right-aligned)
        ui.horizontal(|ui| {
            let sev_bg = match finding.severity {
                Severity::Critical => egui::Color32::from_rgba_unmultiplied(255, 69, 58, 30),
                Severity::High => egui::Color32::from_rgba_unmultiplied(255, 159, 10, 30),
                Severity::Medium => egui::Color32::from_rgba_unmultiplied(255, 214, 10, 30),
                Severity::Low => egui::Color32::from_rgba_unmultiplied(48, 209, 88, 30),
                Severity::Info => egui::Color32::from_rgba_unmultiplied(99, 99, 102, 30),
            };
            badge(ui, tr.severity_name(finding.severity), sev_col, sev_bg);

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(&finding.rule_id)
                        .monospace()
                        .size(11.0)
                        .color(colors::TEXT_TERTIARY),
                );
            });
        });

        ui.add_space(10.0);

        // Rule name — dominant element
        ui.label(
            egui::RichText::new(&finding.rule_name)
                .size(16.0)
                .strong()
                .color(colors::TEXT_PRIMARY),
        );

        ui.add_space(8.0);

        // Detail
        ui.label(
            egui::RichText::new(&finding.detail)
                .size(13.0)
                .color(colors::TEXT_SECONDARY),
        );

        // Evidence — inline code style
        if let Some(ref ev) = finding.evidence {
            ui.add_space(8.0);
            egui::Frame::new()
                .fill(colors::WINDOW_BG)
                .corner_radius(6.0)
                .inner_margin(egui::Margin::symmetric(8, 4))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(ev)
                            .size(11.0)
                            .monospace()
                            .color(colors::TEXT_TERTIARY),
                    );
                });
        }

        // Remediation
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!("\u{2713} {}", tr.fix()))
                    .size(12.0)
                    .strong()
                    .color(colors::GREEN),
            );
            ui.label(
                egui::RichText::new(&finding.remediation)
                    .size(12.0)
                    .color(colors::TEXT_SECONDARY),
            );
        });

        // "View Fix Plan" button — opens remote report
        if let Some(url) = web_url {
            ui.add_space(10.0);
            let url = url.to_string();
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::Button::new(
                        egui::RichText::new(tr.view_fix_plan())
                            .size(12.0)
                            .color(colors::ACCENT_BLUE),
                    )
                    .fill(egui::Color32::TRANSPARENT)
                    .stroke(egui::Stroke::new(1.0, colors::ACCENT_BLUE))
                    .corner_radius(6.0)
                    .min_size(egui::vec2(0.0, 26.0))
                );
                if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                    #[cfg(target_os = "macos")]
                    { let _ = std::process::Command::new("open").arg(&url).spawn(); }
                    #[cfg(target_os = "linux")]
                    { let _ = std::process::Command::new("xdg-open").arg(&url).spawn(); }
                    #[cfg(target_os = "windows")]
                    { let _ = std::process::Command::new("cmd").args(["/C", "start", &url]).spawn(); }
                }
            });
        }
    });

    // Left accent bar
    let card_rect = resp.response.rect;
    let bar_rect = egui::Rect::from_min_size(
        card_rect.left_top(),
        egui::vec2(4.0, card_rect.height()),
    );
    ui.painter().rect_filled(bar_rect, 2.0, sev_col);
}

// ── Background scan logic ──────────────────────────────────────────────

async fn run_scan(tx: mpsc::Sender<ScanMsg>, no_upload: bool, ctx: &egui::Context) {
    let mut all_rules = engine::registry::all_rules();

    let skill_dir = crate::platform::home_dir().join(".claw-guard").join("skills");
    let mut skills_loaded: usize = 0;
    if let Ok(skill_rules) = engine::skill::load_skills(&skill_dir) {
        skills_loaded = skill_rules.len();
        all_rules.extend(skill_rules);
    }

    let total = all_rules.len();

    let mut all_findings = Vec::new();
    let mut rules_run = 0usize;

    for (i, rule) in all_rules.iter().enumerate() {
        rules_run += 1;
        let _ = tx.send(ScanMsg::Progress {
            rule_id: rule.id().to_string(),
            rule_name: rule.name().to_string(),
            current: i + 1,
            total,
        });
        ctx.request_repaint();

        match rule.evaluate() {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => {
                all_findings.push(engine::Finding {
                    rule_id: rule.id().to_string(),
                    rule_name: rule.name().to_string(),
                    category: rule.category(),
                    severity: rule.severity(),
                    status: engine::Status::Error,
                    detail: format!("Rule evaluation failed: {}", e),
                    evidence: None,
                    remediation: rule.remediation().to_string(),
                });
            }
        }
    }

    // Send results immediately — don't wait for cloud
    let mut report = AuditReport::new(all_findings, rules_run, None);
    if skills_loaded > 0 {
        report.skills_loaded = Some(skills_loaded);
    }
    let _ = tx.send(ScanMsg::Done(Box::new(report.clone())));
    ctx.request_repaint();

    // Cloud registration + upload happens async after UI shows results
    if !no_upload {
        let agent_id = crate::get_or_register_agent(crate::API_URL).await.ok();

        if let Some(ref id) = agent_id {
            report.agent_id = Some(id.clone());
            let upload_url = format!("{}/reports", crate::API_URL.trim_end_matches('/'));
            let (web_url, analysis) = match crate::upload_report(&upload_url, &report, true).await {
                Ok(resp) => (resp.web_url, resp.analysis),
                Err(_) => (None, None),
            };
            let _ = tx.send(ScanMsg::CloudUpdate { agent_id, web_url, analysis });
            ctx.request_repaint();
        } else {
            let _ = tx.send(ScanMsg::CloudUpdate { agent_id, web_url: None, analysis: None });
            ctx.request_repaint();
        }
    }
}

fn load_icon() -> egui::IconData {
    let png_bytes = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(png_bytes)
        .expect("Failed to decode embedded icon")
        .into_rgba8();
    let (w, h) = img.dimensions();
    egui::IconData {
        rgba: img.into_raw(),
        width: w,
        height: h,
    }
}

/// Launch the GUI window.
pub fn run_gui() -> eframe::Result {
    let icon = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1050.0, 780.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(icon),
        ..Default::default()
    };

    eframe::run_native(
        &format!("claw-guard v{}", env!("CARGO_PKG_VERSION")),
        options,
        Box::new(|cc| Ok(Box::new(ClawGuardApp::new(cc)))),
    )
}
