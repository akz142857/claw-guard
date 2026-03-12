use crate::engine::{self, Category, Finding, Severity, Status};
use crate::report::AuditReport;
use eframe::egui;
use std::sync::mpsc;

// ── Messages from scan thread → GUI ────────────────────────────────────

enum ScanMsg {
    Progress { rule_id: String, rule_name: String, current: usize, total: usize },
    Done(Box<AuditReport>),
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
}

impl ClawGuardApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        Self {
            state: AppState::Idle,
            progress_text: String::new(),
            progress_current: 0,
            progress_total: 0,
            rx: None,
            no_upload: false,
            filter_category: None,
            friendly_time: String::new(),
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        self.state = AppState::Scanning;
        self.progress_text = "Loading rules...".to_string();
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

// ── Theme ──────────────────────────────────────────────────────────────

fn apply_theme(ctx: &egui::Context) {
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
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.window_margin = egui::Margin::same(20);
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
        center + egui::vec2(0.0, -6.0),
        egui::Align2::CENTER_CENTER,
        format!("{}", score),
        egui::FontId::proportional(28.0),
        color,
    );
    // /100 below
    painter.text(
        center + egui::vec2(0.0, 14.0),
        egui::Align2::CENTER_CENTER,
        "/100",
        egui::FontId::proportional(11.0),
        colors::TEXT_SECONDARY,
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
    ui.add(btn)
}

// ── Badge pill helper ──────────────────────────────────────────────────

fn badge(ui: &mut egui::Ui, label: &str, fg: egui::Color32, bg: egui::Color32) {
    egui::Frame::new()
        .fill(bg)
        .corner_radius(4.0)
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
        .inner_margin(egui::Margin::same(16))
        .shadow(egui::epaint::Shadow {
            offset: [0, 2],
            blur: 8,
            spread: 0,
            color: egui::Color32::from_black_alpha(60),
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

        match &self.state {
            AppState::Idle => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.render_idle(ui, ctx);
                });
            }
            AppState::Scanning => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.render_scanning(ui);
                });
            }
            AppState::Done(report) => {
                let report = report.as_ref();

                egui::SidePanel::left("sidebar")
                    .exact_width(230.0)
                    .frame(
                        egui::Frame::new()
                            .fill(colors::SURFACE)
                            .inner_margin(egui::Margin::same(16)),
                    )
                    .show(ctx, |ui| {
                        wants_reset = Self::render_sidebar(
                            report, &mut self.filter_category, ui,
                        );
                    });

                egui::CentralPanel::default().show(ctx, |ui| {
                    Self::render_main_panel(report, ui, &self.filter_category, &self.friendly_time);
                });
            }
            AppState::Error(e) => {
                let e = e.clone();
                egui::CentralPanel::default().show(ctx, |ui| {
                    wants_reset = Self::render_error(&e, ui);
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

    fn render_idle(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.22).max(40.0));

            // App icon
            let icon_bytes = include_bytes!("../assets/icon.png");
            let icon_image = egui::ColorImage::from_rgba_unmultiplied(
                [256, 256],
                &image::load_from_memory(icon_bytes).unwrap().into_rgba8(),
            );
            let texture = ui.ctx().load_texture("welcome-icon", icon_image, egui::TextureOptions::LINEAR);
            ui.add(egui::Image::new(&texture).fit_to_exact_size(egui::vec2(80.0, 80.0)));
            ui.add_space(12.0);

            // Title
            ui.label(
                egui::RichText::new("ClawGuard")
                    .size(28.0)
                    .strong()
                    .color(colors::TEXT_PRIMARY),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("AI Agent Host Security Audit")
                    .size(13.0)
                    .color(colors::TEXT_SECONDARY),
            );
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .size(11.0)
                    .color(colors::TEXT_TERTIARY),
            );

            ui.add_space(32.0);

            // Settings card (use darker bg so checkbox is visible)
            egui::Frame::new()
                .fill(colors::WINDOW_BG)
                .corner_radius(12.0)
                .inner_margin(egui::Margin::same(16))
                .show(ui, |ui| {
                    ui.set_width(260.0);
                    ui.checkbox(&mut self.no_upload, "Offline mode (no upload)");
                });

            ui.add_space(24.0);

            if accent_button(ui, "Start Scan", 200.0, 44.0).clicked() {
                self.start_scan(ctx);
            }
        });
    }

    // ── Scanning ──

    fn render_scanning(&self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.30).max(60.0));

            ui.label(
                egui::RichText::new("Scanning...")
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
        ui: &mut egui::Ui,
    ) -> bool {
        let mut wants_reset = false;

        // Estimate bottom section height so we can reserve space for it
        let has_agent = report.agent_id.is_some();
        let has_url = report.web_url.is_some();
        // New Scan button: ~50px, separator+spacing: ~20px
        // Agent card: agent ID ~50px, web report btn ~45px, card padding ~30px
        let bottom_h = 70.0 // New Scan + separator + spacing
            + if has_agent && has_url { 130.0 }
              else if has_agent || has_url { 80.0 }
              else { 0.0 };

        let total_h = ui.available_height();

        // ── Top fixed: score gauge + stats ──
        ui.vertical_centered(|ui| {
            paint_score_gauge(ui, report.summary.score, 40.0);
        });

        let score_label = match report.summary.score {
            90..=100 => "Excellent",
            75..=89 => "Good",
            60..=74 => "Fair",
            40..=59 => "Poor",
            _ => "Critical",
        };
        ui.vertical_centered(|ui| {
            ui.label(
                egui::RichText::new(score_label)
                    .size(12.0)
                    .color(score_color(report.summary.score))
                    .strong(),
            );
        });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.label(egui::RichText::new(format!("{}", report.summary.total_rules)).size(11.0).strong().color(colors::TEXT_PRIMARY));
            ui.label(egui::RichText::new("rules").size(11.0).color(colors::TEXT_TERTIARY));
            stat_pill(ui, &format!("{}", report.summary.pass), colors::GREEN);
            ui.label(egui::RichText::new("pass").size(10.0).color(colors::TEXT_TERTIARY));
            stat_pill(ui, &format!("{}", report.summary.fail), colors::RED);
            ui.label(egui::RichText::new("fail").size(10.0).color(colors::TEXT_TERTIARY));
            stat_pill(ui, &format!("{}", report.summary.warn), colors::YELLOW);
            ui.label(egui::RichText::new("warn").size(10.0).color(colors::TEXT_TERTIARY));
        });

        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);

        // ── Middle: scrollable category list (takes remaining space minus bottom) ──
        let used_so_far = total_h - ui.available_height();
        let cat_height = (total_h - used_so_far - bottom_h - 16.0).max(80.0);

        ui.label(
            egui::RichText::new("Categories")
                .size(11.0)
                .color(colors::TEXT_TERTIARY)
                .strong(),
        );
        ui.add_space(2.0);

        egui::ScrollArea::vertical()
            .max_height(cat_height)
            .show(ui, |ui| {
                let all_selected = filter_category.is_none();
                if ui.selectable_label(all_selected, egui::RichText::new("All Findings").size(13.0)).clicked() {
                    *filter_category = None;
                }

                for cat in &report.categories {
                    let is_selected = *filter_category == Some(cat.category);
                    let dot_color = if cat.fail > 0 {
                        colors::RED
                    } else if cat.warn > 0 {
                        colors::YELLOW
                    } else {
                        colors::GREEN
                    };

                    ui.horizontal(|ui| {
                        let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                        ui.painter().circle_filled(dot_rect.center(), 4.0, dot_color);

                        let text = egui::RichText::new(&cat.label).size(12.0);
                        let text = if is_selected { text.strong().color(colors::TEXT_PRIMARY) } else { text };
                        if ui.selectable_label(is_selected, text).clicked() {
                            if is_selected {
                                *filter_category = None;
                            } else {
                                *filter_category = Some(cat.category);
                            }
                        }

                        if cat.fail > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    egui::RichText::new(format!("{}", cat.fail))
                                        .size(11.0)
                                        .color(colors::RED)
                                        .strong(),
                                );
                            });
                        } else if cat.warn > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    egui::RichText::new(format!("{}", cat.warn))
                                        .size(11.0)
                                        .color(colors::YELLOW),
                                );
                            });
                        }
                    });
                }
            });

        // ── Bottom fixed: agent info + buttons ──
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(6.0);

        if has_agent || has_url {
            egui::Frame::new()
                .fill(colors::WINDOW_BG)
                .corner_radius(10.0)
                .inner_margin(egui::Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    if let Some(ref id) = report.agent_id {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new("AGENT ID")
                                    .size(10.0)
                                    .color(colors::TEXT_TERTIARY)
                                    .strong(),
                            );
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    egui::RichText::new("click to copy")
                                        .size(9.0)
                                        .color(colors::TEXT_TERTIARY),
                                );
                            });
                        });
                        ui.add_space(2.0);
                        let btn = egui::Button::new(
                            egui::RichText::new(id)
                                .size(10.0)
                                .monospace()
                                .color(colors::TEXT_SECONDARY),
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .frame(false);
                        let resp = ui.add(btn);
                        if resp.clicked() {
                            ui.ctx().copy_text(id.clone());
                        }
                        resp.on_hover_cursor(egui::CursorIcon::Copy);
                    }

                    if has_agent && has_url {
                        ui.add_space(6.0);
                    }

                    if let Some(ref url) = report.web_url {
                        let w = ui.available_width();
                        let resp = ui.vertical_centered(|ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("View Web Report \u{2197}")
                                    .size(12.0)
                                    .color(egui::Color32::WHITE)
                                    .strong(),
                            )
                            .fill(colors::ACCENT_BLUE)
                            .corner_radius(8.0)
                            .min_size(egui::vec2(w, 30.0));
                            ui.add(btn)
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

            ui.add_space(6.0);
        }

        ui.vertical_centered(|ui| {
            let btn = egui::Button::new(
                egui::RichText::new("New Scan")
                    .size(13.0)
                    .color(colors::TEXT_PRIMARY),
            )
            .fill(colors::SURFACE_HOVER)
            .corner_radius(8.0)
            .min_size(egui::vec2(ui.available_width(), 34.0));
            if ui.add(btn).clicked() {
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
    ) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(16.0);

            // Section heading
            let heading_text = match filter_category {
                Some(cat) => format!("{}", cat),
                None => "All Findings".to_string(),
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

            ui.add_space(16.0);

            // ── Finding cards (issues) ──
            let issues: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.status != Status::Pass && f.status != Status::Skip)
                .filter(|f| filter_category.map_or(true, |cat| f.category == cat))
                .collect();

            if issues.is_empty() && filter_category.is_some() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(
                        egui::RichText::new("No issues in this category")
                            .size(14.0)
                            .color(colors::TEXT_TERTIARY),
                    );
                });
            }

            for finding in &issues {
                render_finding_card(ui, finding);
                ui.add_space(8.0);
            }

            // ── Passed (compact green rows) ──
            let passed: Vec<&Finding> = report
                .findings
                .iter()
                .filter(|f| f.status == Status::Pass)
                .filter(|f| filter_category.map_or(true, |cat| f.category == cat))
                .collect();

            if !passed.is_empty() {
                ui.add_space(16.0);
                ui.collapsing(
                    egui::RichText::new(format!("Passed ({})", passed.len()))
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
                ui.add_space(20.0);
                ui.label(
                    egui::RichText::new("AI Analysis")
                        .size(18.0)
                        .strong()
                        .color(colors::TEXT_PRIMARY),
                );
                ui.add_space(8.0);

                // Executive summary card
                card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width() - 4.0);
                    ui.label(
                        egui::RichText::new("Executive Summary")
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
                        egui::RichText::new("Attack Chains")
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
                        egui::RichText::new("Priority Fixes")
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
                        egui::RichText::new("Context Notes")
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

    fn render_error(err_msg: &str, ui: &mut egui::Ui) -> bool {
        let mut wants_reset = false;
        ui.vertical_centered(|ui| {
            let avail = ui.available_height();
            ui.add_space((avail * 0.30).max(60.0));

            ui.label(
                egui::RichText::new("Scan Error")
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
            if accent_button(ui, "Back", 120.0, 36.0).clicked() {
                wants_reset = true;
            }
        });
        wants_reset
    }
}

// ── Stat pill (small colored number) ───────────────────────────────────

fn stat_pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.label(
        egui::RichText::new(text)
            .size(12.0)
            .strong()
            .color(color),
    );
}

// ── Finding card ───────────────────────────────────────────────────────

fn render_finding_card(ui: &mut egui::Ui, finding: &Finding) {
    let sev_col = severity_color(finding.severity);

    // Outer frame: card with left colored border
    let frame = egui::Frame::new()
        .fill(colors::SURFACE)
        .corner_radius(12.0)
        .inner_margin(egui::Margin {
            left: 16,
            right: 16,
            top: 14,
            bottom: 14,
        })
        .shadow(egui::epaint::Shadow {
            offset: [0, 1],
            blur: 6,
            spread: 0,
            color: egui::Color32::from_black_alpha(40),
        });

    let resp = frame.show(ui, |ui| {
        ui.set_width(ui.available_width() - 4.0);

        // Row 1: badges + rule ID
        ui.horizontal(|ui| {
            // Status badge
            let (status_label, status_fg) = match finding.status {
                Status::Fail => ("FAIL", colors::RED),
                Status::Warn => ("WARN", colors::YELLOW),
                Status::Error => ("ERR", colors::PURPLE),
                _ => ("", colors::TEXT_SECONDARY),
            };
            let status_bg = match finding.status {
                Status::Fail => egui::Color32::from_rgba_unmultiplied(255, 69, 58, 30),
                Status::Warn => egui::Color32::from_rgba_unmultiplied(255, 214, 10, 30),
                Status::Error => egui::Color32::from_rgba_unmultiplied(191, 90, 242, 30),
                _ => egui::Color32::from_rgba_unmultiplied(99, 99, 102, 30),
            };
            badge(ui, status_label, status_fg, status_bg);

            // Severity badge
            let sev_bg = match finding.severity {
                Severity::Critical => egui::Color32::from_rgba_unmultiplied(255, 69, 58, 30),
                Severity::High => egui::Color32::from_rgba_unmultiplied(255, 159, 10, 30),
                Severity::Medium => egui::Color32::from_rgba_unmultiplied(255, 214, 10, 30),
                Severity::Low => egui::Color32::from_rgba_unmultiplied(48, 209, 88, 30),
                Severity::Info => egui::Color32::from_rgba_unmultiplied(99, 99, 102, 30),
            };
            badge(ui, &format!("{}", finding.severity), sev_col, sev_bg);

            ui.label(
                egui::RichText::new(&finding.rule_id)
                    .strong()
                    .monospace()
                    .size(12.0)
                    .color(colors::TEXT_SECONDARY),
            );
        });

        ui.add_space(6.0);

        // Rule name
        ui.label(
            egui::RichText::new(&finding.rule_name)
                .size(14.0)
                .color(colors::TEXT_PRIMARY),
        );

        ui.add_space(4.0);

        // Detail
        ui.label(
            egui::RichText::new(&finding.detail)
                .size(13.0)
                .color(colors::TEXT_SECONDARY),
        );

        // Evidence
        if let Some(ref ev) = finding.evidence {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("Evidence: {}", ev))
                    .size(12.0)
                    .monospace()
                    .color(colors::TEXT_TERTIARY),
            );
        }

        // Remediation
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new("\u{2713} Fix:")
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
    });

    // Paint left accent bar after layout so we know the final rect
    let card_rect = resp.response.rect;
    let bar_rect = egui::Rect::from_min_size(
        card_rect.left_top(),
        egui::vec2(3.0, card_rect.height()),
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

    let agent_id = if !no_upload {
        match crate::get_or_register_agent(crate::API_URL).await {
            Ok(id) => Some(id),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut report = AuditReport::new(all_findings, rules_run, agent_id.clone());
    if skills_loaded > 0 {
        report.skills_loaded = Some(skills_loaded);
    }

    if !no_upload {
        if agent_id.is_some() {
            let upload_url = format!("{}/reports", crate::API_URL.trim_end_matches('/'));
            match crate::upload_report(&upload_url, &report, true).await {
                Ok(upload_resp) => {
                    if let Some(analysis) = upload_resp.analysis {
                        report.analysis = Some(analysis);
                    }
                    if upload_resp.web_url.is_some() {
                        report.web_url = upload_resp.web_url;
                    }
                }
                Err(_) => {}
            }
        }
    }

    let _ = tx.send(ScanMsg::Done(Box::new(report)));
    ctx.request_repaint();
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
