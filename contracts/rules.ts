/**
 * 行为关联分析规则 —— 前后端共享契约
 * 4 大类 14 个分析场景
 */

export type RuleCategory = "attack" | "c2" | "data" | "baseline";
export type Severity = "critical" | "high" | "medium" | "low";

export interface AnalysisRuleDef {
  code: string;
  name: string;
  category: RuleCategory;
  severity: Severity;
  desc: string;
  logic: string;
  fields: string[];
  thresholds: Record<string, string | number>;
}

export const RULE_CATEGORY_META: Record<RuleCategory, { label: string; en: string; desc: string }> = {
  attack: { label: "入侵攻击类", en: "INTRUSION", desc: "扫描、爆破、横向移动与 Web 攻击探测" },
  c2: { label: "C&C 与恶意通信类", en: "C2 & MALICIOUS COMM", desc: "心跳、DNS 隧道、DGA 与隐蔽通道" },
  data: { label: "数据安全类", en: "DATA SECURITY", desc: "数据外泄、异常大流量与明文敏感协议" },
  baseline: { label: "异常行为基线类", en: "BASELINE ANOMALY", desc: "时间、地理与流量基线偏离" },
};

export const ANALYSIS_RULES: AnalysisRuleDef[] = [
  {
    code: "PORT_SCAN",
    name: "端口扫描检测",
    category: "attack",
    severity: "high",
    desc: "识别单源主机在短窗口内触达大量不同目的端口的扫描行为",
    logic: "按源 IP 聚合 10 分钟窗口：独立目的端口数 ≥ 阈值 且 连接失败率 > 60% 时命中；关联 SYN 计数、小包占比与端口离散度区分 SYN 扫描与全连接扫描",
    fields: ["srcIp", "hostUniqueDstPort", "hostFailConnRatio", "synCount", "rstCount", "smallPktRatio", "portDiversity", "duration"],
    thresholds: { uniquePorts: 30, failRatio: 0.6, windowMin: 10 },
  },
  {
    code: "LATERAL_MOVE",
    name: "横向移动检测",
    category: "attack",
    severity: "critical",
    desc: "发现内网主机通过 SMB/RDP/SSH/WMI 等管理服务批量触达其他内网主机",
    logic: "过滤内到内会话且目的端口 ∈ {22,135,139,445,3389,5985}：源主机 1 小时扇出度 ≥ 阈值 或 同端口触达主机数 ≥ 阈值 时命中，输出被触达主机清单",
    fields: ["srcIp", "dstIp", "dstPort", "direction", "hostFanOut", "samePortHitCount", "appProtocol", "authSuccess"],
    thresholds: { fanOut: 12, samePortHosts: 8, windowMin: 60 },
  },
  {
    code: "BRUTE_FORCE",
    name: "暴力破解检测",
    category: "attack",
    severity: "high",
    desc: "检测针对 SSH/RDP/HTTP 认证的高频失败登录尝试",
    logic: "按 源IP+目的IP+目的端口 聚合：认证尝试累计 ≥ 阈值 且 认证成功率 < 10% 时命中；结合会话短时长、RST 关闭与 401/403 计数确认",
    fields: ["srcIp", "dstIp", "dstPort", "authAttempts", "authSuccess", "closeReason", "httpAuthFailCount", "duration"],
    thresholds: { attempts: 20, successRatio: 0.1, windowMin: 30 },
  },
  {
    code: "WEB_ATTACK",
    name: "Web 攻击探测",
    category: "attack",
    severity: "high",
    desc: "识别 URI 中携带 SQL 注入、XSS、路径穿越等攻击载荷的 HTTP 会话",
    logic: "匹配 httpHasSqlPattern / httpHasXssPattern / httpHasPathTraversal 任一命中，或 URI 长度 > 200 且状态码 4xx 聚集；按源 IP 聚合攻击类型分布",
    fields: ["srcIp", "httpUri", "httpUriLen", "httpHasSqlPattern", "httpHasXssPattern", "httpHasPathTraversal", "httpStatus", "httpUserAgent"],
    thresholds: { uriLen: 200, minHits: 3 },
  },
  {
    code: "C2_BEACON",
    name: "C&C 心跳检测",
    category: "c2",
    severity: "critical",
    desc: "发现与外部地址保持固定周期、低抖动、小包对称通信的 Beacon 行为",
    logic: "按 源IP+目的IP 聚合 ≥ 10 条会话：间隔变异系数 < 0.15、周期性得分 ≥ 80、上行平均包长 < 300B 且字节对称度 > 0.5 时命中",
    fields: ["srcIp", "dstIp", "intervalMean", "intervalStd", "intervalCv", "periodicityScore", "avgPktLenUp", "pairByteSymmetry", "pairSessionCount"],
    thresholds: { minSessions: 10, intervalCv: 0.15, periodicity: 80, avgPktLen: 300 },
  },
  {
    code: "DNS_TUNNEL",
    name: "DNS 隧道检测",
    category: "c2",
    severity: "critical",
    desc: "识别利用 DNS 查询/应答承载数据的隧道通信",
    logic: "按源 IP 聚合 DNS 会话：超长查询次数 ≥ 阈值 或 TXT 查询占比 > 30%，且域名熵 > 4.2bit、响应报文均值 > 300B 时命中",
    fields: ["srcIp", "dnsQueryName", "dnsQueryLen", "dnsSubdomainLen", "dnsNameEntropy", "dnsTxtCount", "dnsLongQueryCount", "dnsResponseSize", "dnsQueryType"],
    thresholds: { longQueries: 20, txtRatio: 0.3, entropy: 4.2, respSize: 300 },
  },
  {
    code: "DGA_DOMAIN",
    name: "DGA 域名检测",
    category: "c2",
    severity: "high",
    desc: "发现主机大量查询高熵随机域名且解析失败率高的 DGA 行为",
    logic: "按源 IP 聚合：NXDOMAIN 率 > 50%、独立域名数 ≥ 阈值 且 域名平均熵 > 3.8bit 时命中；输出可疑域名样本",
    fields: ["srcIp", "dnsIsNxdomain", "dnsNxdomainRatio", "dnsUniqueDomains", "dnsNameEntropy", "dnsDigitRatio", "dnsQueryName"],
    thresholds: { nxdomainRatio: 0.5, uniqueDomains: 50, entropy: 3.8 },
  },
  {
    code: "COVERT_CHANNEL",
    name: "隐蔽通道检测",
    category: "c2",
    severity: "medium",
    desc: "检测知名服务运行在非常用端口或协议-端口不匹配的伪装通信",
    logic: "匹配：HTTPS 指纹出现在非 443 端口、HTTP 明文出现在高端口、或 TLS 会话 SNI 与证书不匹配；按目的 IP+端口 聚合命中次数",
    fields: ["dstIp", "dstPort", "appProtocol", "tlsSni", "tlsCertSnMatch", "tlsJa3", "tlsCertSelfSigned", "httpHost"],
    thresholds: { minHits: 2 },
  },
  {
    code: "DATA_EXFIL",
    name: "数据外泄检测",
    category: "data",
    severity: "critical",
    desc: "发现内网主机向外部新目的持续大比例上传的可疑外泄行为",
    logic: "按 源IP+目的IP 聚合：上行总量 ≥ 阈值、上下行字节比 > 4、目的为外部且 7 天内首次出现时命中；关联文件传输计数与载荷熵",
    fields: ["srcIp", "dstIp", "upBytes", "downBytes", "upDownByteRatio", "hostUpBytesTotal", "isNewDestination", "payloadEntropyUp", "fileTransferCount", "direction"],
    thresholds: { upBytes: 104857600, ratio: 4, windowMin: 60 },
  },
  {
    code: "BULK_TRANSFER",
    name: "异常大流量传输",
    category: "data",
    severity: "high",
    desc: "识别单会话或单主机超出基线的批量数据传输",
    logic: "单会话总字节 ≥ 阈值 或 主机窗口总字节超过基线 5 倍时命中；区分上传型与下载型，标注速率峰值",
    fields: ["srcIp", "dstIp", "totalBytes", "upBytes", "downBytes", "upByteRate", "downByteRate", "hostBaselineDeviation", "duration"],
    thresholds: { sessionBytes: 157286400, baselineFactor: 5 },
  },
  {
    code: "CLEARTEXT_ABUSE",
    name: "敏感协议滥用",
    category: "data",
    severity: "medium",
    desc: "发现 FTP/Telnet/HTTP 等明文协议传输认证信息或文件的行为",
    logic: "匹配 isCleartextProto = true 且存在认证尝试或文件传输的会话；按源主机聚合涉及服务与数据量",
    fields: ["srcIp", "dstIp", "appProtocol", "isCleartextProto", "authAttempts", "fileTransferCount", "fileName", "upBytes"],
    thresholds: { minSessions: 2 },
  },
  {
    code: "OFF_HOURS",
    name: "非工作时间活动",
    category: "baseline",
    severity: "medium",
    desc: "发现主机在深夜/周末产生显著出站流量的异常作息",
    logic: "按源 IP 聚合：深夜会话占比 > 40% 且 深夜上行字节 > 10MB 时命中；输出活跃时段分布直方数据",
    fields: ["srcIp", "hourOfDay", "isNight", "isWorkHour", "nightSessionRatio", "upBytes", "weekendRatio"],
    thresholds: { nightRatio: 0.4, nightBytes: 10485760 },
  },
  {
    code: "GEO_ANOMALY",
    name: "地理位置异常",
    category: "baseline",
    severity: "high",
    desc: "发现与高危地区、Tor 出口或已知恶意基础设施的通信",
    logic: "匹配 dstIsHighRiskGeo / dstIsTor / dstIsKnownC2 任一为真，或威胁评分 ≥ 80 的会话；按目的国家/地区聚合",
    fields: ["srcIp", "dstIp", "dstCountry", "dstIsHighRiskGeo", "dstIsTor", "dstIsKnownC2", "dstThreatScore", "ipReputation", "geoDistanceKm"],
    thresholds: { threatScore: 80 },
  },
  {
    code: "BASELINE_DEVIATION",
    name: "流量基线偏离",
    category: "baseline",
    severity: "medium",
    desc: "基于同类主机 7 日基线，发现流量量级显著偏离的主机",
    logic: "计算主机窗口上行总量与基线比值：偏离倍数 ≥ 阈值 且 绝对增量 > 50MB 时命中；按偏离倍数排序输出",
    fields: ["srcIp", "hostUpBytesTotal", "hostUpBytesBaseline", "hostBaselineDeviation", "hostSessionCount", "activeRatio"],
    thresholds: { deviation: 8, minDelta: 52428800 },
  },
];

export const SEVERITY_META: Record<Severity, { label: string; order: number }> = {
  critical: { label: "严重", order: 4 },
  high: { label: "高危", order: 3 },
  medium: { label: "中危", order: 2 },
  low: { label: "低危", order: 1 },
};
