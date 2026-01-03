export type ModuleState = "available" | "planned";

export interface ModuleItem {
  id: string;
  name: string;
  description: string;
  state: ModuleState;
}

export const MODULES: readonly ModuleItem[] = [
  {
    id: "overview",
    name: "总览",
    description: "项目状态、模块清单与快速入口",
    state: "available",
  },
  {
    id: "flag-detector",
    name: "Flag Detector",
    description: "明文/常规编码 Flag 文本检测（第一个模块）",
    state: "available",
  },
  {
    id: "usb",
    name: "USB 流量还原",
    description: "USB 键盘/鼠标等 HID 轨迹还原",
    state: "planned",
  },
  {
    id: "wifi",
    name: "无线流量破解",
    description: "暴力破解密码后自动分析",
    state: "planned",
  },
  {
    id: "sql-blind",
    name: "SQL 盲注流量分析",
    description: "支持二分法/布尔盲注，自动识别 Flag",
    state: "planned",
  },
  {
    id: "icmp",
    name: "ICMP 流量分析",
    description: "TTL / DATA.len / DATA / ICMP.code",
    state: "planned",
  },
  {
    id: "telnet",
    name: "Telnet 流量分析",
    description: "会话还原与关键内容提取",
    state: "planned",
  },
  {
    id: "ftp",
    name: "FTP/FTP-DATA 流量分析",
    description: "控制信道 + 数据信道对象识别",
    state: "planned",
  },
  {
    id: "smtp",
    name: "SMTP 流量分析",
    description: "识别登录成功的用户名与密码",
    state: "planned",
  },
  {
    id: "cobaltstrike",
    name: "CS 通信解密分析",
    description: "需要提供 .cobaltstrike.beacon_keys",
    state: "planned",
  },
  {
    id: "bluetooth",
    name: "蓝牙流量分析",
    description: "蓝牙协议栈内容解析与对象提取",
    state: "planned",
  },
  {
    id: "ics",
    name: "工业控制流量分析",
    description: "MMS / modbus / iec60870 / mqtt / s7com / OMRON",
    state: "planned",
  },
  {
    id: "tls-keylog",
    name: "TLS keylog 解密分析",
    description: "使用 keylog_file 自动解密流量并分析",
    state: "planned",
  },
  {
    id: "extract-files",
    name: "一键分离文件",
    description: "导出对象可能存在问题，支持手动导出兜底",
    state: "planned",
  },
  {
    id: "export-objects",
    name: "一键导出协议对象",
    description: "dicom / ftp-data / http / imf / smb / tftp",
    state: "planned",
  },
  {
    id: "fix-pcap",
    name: "一键修复错误流量包",
    description: "尽量恢复异常/损坏流量包可解析性",
    state: "planned",
  },
  {
    id: "port-scan",
    name: "统计端口扫描",
    description: "统计开放端口与扫描特征",
    state: "planned",
  },
  {
    id: "http-uri",
    name: "统计 HTTP URI",
    description: "URI 频次、路径聚类、参数特征统计",
    state: "planned",
  },
  {
    id: "dns",
    name: "DNS 流量分析",
    description: "域名、查询类型、可疑模式识别",
    state: "planned",
  },
  {
    id: "http-save",
    name: "自动保存 HTTP 传输文件",
    description: "自动落盘 HTTP 对象与元信息",
    state: "planned",
  },
  {
    id: "webshell",
    name: "WebShell 流量识别/解密",
    description: "一键识别并解密常见 WebShell 通信",
    state: "planned",
  },
  {
    id: "etl-pcapng",
    name: "ETL → PCAPNG",
    description: "一键转换 etl 为 pcapng",
    state: "planned",
  },
  {
    id: "udp",
    name: "UDP 协议数据分析",
    description: "通用 UDP 数据统计与特征提取",
    state: "planned",
  },
  {
    id: "http-cred",
    name: "专项：HTTP 登录账号密码",
    description: "识别登录成功的账号与密码（流量侧）",
    state: "planned",
  },
] as const;
