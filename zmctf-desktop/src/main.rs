use eframe::egui;
use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::time::Duration;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "ZMctf Desktop",
        native_options,
        Box::new(|cc| Ok(Box::new(ZmctfApp::new(cc)))),
    )
}

const ACCENT: egui::Color32 = egui::Color32::from_rgb(0, 255, 65);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleState {
    Available,
    Planned,
}

struct ModuleItem {
    name: &'static str,
    description: &'static str,
    state: ModuleState,
}

const MODULE_CATALOG: &[ModuleItem] = &[
    ModuleItem {
        name: "Flag Detector",
        description: "明文/常规编码 Flag 文本检测（第一个模块）",
        state: ModuleState::Available,
    },
    ModuleItem {
        name: "USB 流量还原",
        description: "USB 键盘/鼠标等 HID 轨迹还原",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "无线流量破解",
        description: "暴力破解密码后自动分析",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "SQL 盲注流量分析",
        description: "支持二分法/布尔盲注，自动识别 Flag",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "ICMP 流量分析",
        description: "TTL / DATA.len / DATA / ICMP.code",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "Telnet 流量分析",
        description: "会话还原与关键内容提取",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "FTP/FTP-DATA 流量分析",
        description: "控制信道 + 数据信道对象识别",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "SMTP 流量分析",
        description: "识别登录成功的用户名与密码",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "CS 通信解密分析",
        description: "需要提供 .cobaltstrike.beacon_keys",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "蓝牙流量分析",
        description: "蓝牙协议栈内容解析与对象提取",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "工业控制流量分析",
        description: "MMS / modbus / iec60870 / mqtt / s7com / OMRON",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "TLS keylog 解密分析",
        description: "使用 keylog_file 自动解密流量并分析",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "一键分离文件",
        description: "导出对象可能存在问题，支持手动导出兜底",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "一键导出协议对象",
        description: "dicom / ftp-data / http / imf / smb / tftp",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "一键修复错误流量包",
        description: "尽量恢复异常/损坏流量包可解析性",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "统计端口扫描",
        description: "统计开放端口与扫描特征",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "统计 HTTP URI",
        description: "URI 频次、路径聚类、参数特征统计",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "DNS 流量分析",
        description: "域名、查询类型、可疑模式识别",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "自动保存 HTTP 传输文件",
        description: "自动落盘 HTTP 对象与元信息",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "WebShell 流量识别/解密",
        description: "一键识别并解密常见 WebShell 通信",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "ETL → PCAPNG",
        description: "一键转换 etl 为 pcapng",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "UDP 协议数据分析",
        description: "通用 UDP 数据统计与特征提取",
        state: ModuleState::Planned,
    },
    ModuleItem {
        name: "专项：HTTP 登录账号密码",
        description: "识别登录成功的账号与密码（流量侧）",
        state: ModuleState::Planned,
    },
];

struct ZmctfApp {
    modules: &'static [ModuleItem],
    active_module_index: usize,
    flag_detector_ui: FlagDetectorUi,
}

impl ZmctfApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_fonts(&cc.egui_ctx);
        apply_dark_theme(&cc.egui_ctx);

        Self {
            modules: MODULE_CATALOG,
            active_module_index: 0,
            flag_detector_ui: FlagDetectorUi::new(),
        }
    }
}

impl eframe::App for ZmctfApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("zmctf_sidebar")
            .resizable(false)
            .default_width(240.0)
            .show(ctx, |ui| {
                ui.heading("ZMctf");
                ui.label(egui::RichText::new("模块化取证分析套件").weak());
                ui.add_space(10.0);

                ui.separator();

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(8.0, 8.0);

                    for (index, module_item) in self.modules.iter().enumerate() {
                        let selected = index == self.active_module_index;
                        let tag = match module_item.state {
                            ModuleState::Available => {
                                egui::RichText::new("可用").color(ACCENT).strong()
                            }
                            ModuleState::Planned => egui::RichText::new("规划中").weak(),
                        };

                        let resp = ui
                            .add(egui::SelectableLabel::new(selected, module_item.name))
                            .on_hover_text(module_item.description);
                        ui.horizontal(|ui| {
                            ui.add_space(2.0);
                            ui.label(tag);
                        });

                        if resp.clicked() {
                            self.active_module_index = index;
                        }

                        ui.label(egui::RichText::new(module_item.description).weak());
                        ui.separator();
                    }
                });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(active) = self.modules.get(self.active_module_index) else {
                ui.heading("模块");
                ui.label("未选择模块。");
                return;
            };

            ui.horizontal(|ui| {
                ui.heading(active.name);
                ui.add_space(8.0);
                match active.state {
                    ModuleState::Available => {
                        ui.label(egui::RichText::new("可用").color(ACCENT).strong());
                    }
                    ModuleState::Planned => {
                        ui.label(egui::RichText::new("规划中").weak());
                    }
                }
            });
            ui.label(egui::RichText::new(active.description).weak());
            ui.add_space(10.0);
            ui.separator();

            match active.state {
                ModuleState::Available => {
                    if active.name == "Flag Detector" {
                        self.flag_detector_ui.ui(ctx, ui);
                    } else {
                        ui.label("该模块已标记为可用，但尚未实现界面。");
                    }
                }
                ModuleState::Planned => {
                    ui.label("该模块尚未实现：此处先占位，用于后续统一接入。");
                    ui.add_space(8.0);
                    ui.label("建议下一步：先定义统一的“模块接口契约”（输入/输出/日志/产物路径）。");
                }
            }
        });
    }
}

#[derive(Debug, Serialize)]
struct AnalyzeRequest {
    content: String,
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeResponse {
    success: bool,
    flags: Vec<AnalyzeFlag>,
    logs: Vec<AnalyzeLogEntry>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeFlag {
    content: String,
    confidence: f64,
    source: String,
    encoding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeLogEntry {
    timestamp: String,
    level: String,
    module: String,
    action: String,
}

struct FlagDetectorUi {
    api_base_url: String,
    input_text: String,
    last_response: Option<AnalyzeResponse>,
    status_line: String,
    pending_rx: Option<mpsc::Receiver<Result<AnalyzeResponse, String>>>,
}

impl FlagDetectorUi {
    fn new() -> Self {
        Self {
            api_base_url: "http://127.0.0.1:8080".to_string(),
            input_text: String::new(),
            last_response: None,
            status_line: "提示：先启动后端 `flag-detector/core` 的 `zmctf-server`。".to_string(),
            pending_rx: None,
        }
    }

    fn ui(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        self.poll_response(ctx);

        ui.horizontal(|ui| {
            ui.label("API 基地址：");
            ui.text_edit_singleline(&mut self.api_base_url);
        });

        ui.add_space(8.0);

        ui.label("输入文本：");
        ui.add(
            egui::TextEdit::multiline(&mut self.input_text)
                .desired_rows(10)
                .hint_text("粘贴待分析文本（可含明文/常规编码）")
                .lock_focus(true),
        );

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let analyze_enabled = self.pending_rx.is_none() && !self.input_text.is_empty();
            if ui
                .add_enabled(analyze_enabled, egui::Button::new("分析"))
                .clicked()
            {
                self.request_analyze();
            }

            if ui.button("清空").clicked() {
                self.input_text.clear();
            }

            if ui.button("清空结果").clicked() {
                self.last_response = None;
            }
        });

        ui.add_space(8.0);
        ui.label(egui::RichText::new(&self.status_line).weak());

        ui.add_space(10.0);
        ui.separator();

        let Some(resp) = &self.last_response else {
            ui.label("暂无结果。");
            return;
        };

        ui.horizontal(|ui| {
            ui.label("success：");
            ui.label(format!("{}", resp.success));
            ui.add_space(12.0);
            ui.label("flags：");
            ui.label(format!("{}", resp.flags.len()));
        });

        ui.add_space(8.0);
        ui.heading("Flag 列表");
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .show(ui, |ui| {
                for item in &resp.flags {
                    ui.group(|ui| {
                        ui.label(egui::RichText::new(&item.content).strong());
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("confidence：").weak());
                            ui.label(format!("{:.3}", item.confidence));
                        });
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("source：").weak());
                            ui.label(&item.source);
                        });
                        if let Some(encoding) = &item.encoding {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("encoding：").weak());
                                ui.label(encoding);
                            });
                        }
                    });
                    ui.add_space(8.0);
                }
            });

        ui.add_space(10.0);
        ui.heading("日志");
        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                for entry in &resp.logs {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&entry.timestamp).weak());
                        ui.label(egui::RichText::new(&entry.level).weak());
                        ui.label(egui::RichText::new(&entry.module).weak());
                        ui.label(&entry.action);
                    });
                }
            });
    }

    fn poll_response(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.pending_rx else {
            return;
        };

        match rx.try_recv() {
            Ok(result) => {
                self.pending_rx = None;
                match result {
                    Ok(resp) => {
                        self.status_line = format!("分析完成：发现 {} 个 flag。", resp.flags.len());
                        self.last_response = Some(resp);
                    }
                    Err(err) => {
                        self.status_line = format!("分析失败：{err}");
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.pending_rx = None;
                self.status_line = "分析失败：后台任务中断。".to_string();
            }
        }
    }

    fn request_analyze(&mut self) {
        self.status_line = "正在分析…".to_string();
        self.last_response = None;

        let request = AnalyzeRequest {
            content: self.input_text.clone(),
            mode: None,
        };

        let base_url = self.api_base_url.clone();
        let (tx, rx) = mpsc::channel();
        self.pending_rx = Some(rx);

        std::thread::spawn(move || {
            let result = analyze_via_http(&base_url, &request);
            let _ = tx.send(result);
        });
    }
}

fn analyze_via_http(base_url: &str, request: &AnalyzeRequest) -> Result<AnalyzeResponse, String> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{base}/api/analyze");

    let body = serde_json::to_string(request).map_err(|e| e.to_string())?;

    let resp = ureq::post(&url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(15))
        .send_string(&body);

    match resp {
        Ok(r) => {
            let text = r.into_string().map_err(|e| e.to_string())?;
            serde_json::from_str::<AnalyzeResponse>(&text).map_err(|e| e.to_string())
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            Err(format!("HTTP {code}: {text}"))
        }
        Err(e) => Err(e.to_string()),
    }
}

fn apply_dark_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();

    let border = egui::Color32::from_rgb(31, 31, 31);
    let panel = egui::Color32::from_rgb(13, 13, 13);

    visuals.window_fill = panel;
    visuals.panel_fill = panel;
    visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, border);
    visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, border);
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    visuals.selection.bg_fill = ACCENT.linear_multiply(0.25);
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);

    ctx.set_visuals(visuals);
}

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let font_key = "zmctf_cjk";

    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &[
            "C:\\Windows\\Fonts\\simhei.ttf",
            "C:\\Windows\\Fonts\\simfang.ttf",
            "C:\\Windows\\Fonts\\simkai.ttf",
            "C:\\Windows\\Fonts\\simsunb.ttf",
            "C:\\Windows\\Fonts\\msyh.ttc",
        ]
    } else if cfg!(target_os = "macos") {
        &[
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
            "/System/Library/Fonts/STHeiti Medium.ttc",
        ]
    } else {
        &[
            "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/arphic/ukai.ttc",
            "/usr/share/fonts/truetype/arphic/uming.ttc",
        ]
    };

    let mut loaded = false;
    for path in candidates {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert(font_key.to_owned(), egui::FontData::from_owned(bytes));
            loaded = true;
            break;
        }
    }

    if !loaded {
        return;
    }

    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        family.insert(0, font_key.to_owned());
    }
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
        family.push(font_key.to_owned());
    }

    ctx.set_fonts(fonts);
}
