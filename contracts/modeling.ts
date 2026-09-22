/**
 * 可视化建模契约 —— 维度、度量、聚合与算子白名单
 * 前后端共享：前端渲染构建向导，后端据此安全地拼装聚合查询
 */

export type AggFn = "count" | "sum" | "avg" | "max" | "min" | "countDistinct";
export type FilterOp = "eq" | "ne" | "gt" | "gte" | "lt" | "lte" | "like";

export interface DimensionDef {
  key: string;
  label: string;
  source: "column" | "meta";
  numeric?: boolean;
}

export interface MetricFieldDef {
  key: string;
  label: string;
  source: "column" | "meta" | "computed";
  aggs: AggFn[];
}

/** 可作为分组维度的字段 */
export const DIMENSIONS: DimensionDef[] = [
  { key: "srcIp", label: "源 IP", source: "column" },
  { key: "dstIp", label: "目的 IP", source: "column" },
  { key: "srcPort", label: "源端口", source: "column" },
  { key: "dstPort", label: "目的端口", source: "column" },
  { key: "protocol", label: "传输层协议", source: "column" },
  { key: "appProtocol", label: "应用层协议", source: "column" },
  { key: "direction", label: "会话方向", source: "column" },
  { key: "dstCountry", label: "目的国家/地区", source: "column" },
  { key: "hourOfDay", label: "小时（0-23）", source: "meta", numeric: true },
  { key: "isNight", label: "是否深夜", source: "meta" },
  { key: "isWorkHour", label: "是否工作时间", source: "meta" },
  { key: "dnsQueryType", label: "DNS 查询类型", source: "meta" },
  { key: "dnsRcode", label: "DNS 响应码", source: "meta" },
  { key: "dnsTld", label: "DNS 顶级域", source: "meta" },
  { key: "tlsVersion", label: "TLS 版本", source: "meta" },
  { key: "httpMethod", label: "HTTP 方法", source: "meta" },
  { key: "httpStatus", label: "HTTP 状态码", source: "meta", numeric: true },
  { key: "closeReason", label: "关闭方式", source: "meta" },
  { key: "tcpState", label: "会话终态", source: "meta" },
  { key: "sensorId", label: "采集探针", source: "meta" },
  { key: "ipReputation", label: "IP 信誉", source: "meta" },
  { key: "dstAsnOrg", label: "目的 ASN 组织", source: "meta" },
];

/** 可作为度量的字段 */
export const METRIC_FIELDS: MetricFieldDef[] = [
  { key: "*", label: "会话数", source: "column", aggs: ["count"] },
  { key: "upBytes", label: "上行字节", source: "column", aggs: ["sum", "avg", "max", "min"] },
  { key: "downBytes", label: "下行字节", source: "column", aggs: ["sum", "avg", "max", "min"] },
  { key: "totalBytes", label: "总字节", source: "computed", aggs: ["sum", "avg", "max", "min"] },
  { key: "upPackets", label: "上行包数", source: "column", aggs: ["sum", "avg", "max", "min"] },
  { key: "downPackets", label: "下行包数", source: "column", aggs: ["sum", "avg", "max", "min"] },
  { key: "duration", label: "会话时长", source: "column", aggs: ["sum", "avg", "max", "min"] },
  { key: "threatScore", label: "威胁评分", source: "column", aggs: ["avg", "max"] },
  { key: "srcIp", label: "独立源 IP", source: "column", aggs: ["countDistinct"] },
  { key: "dstIp", label: "独立目的 IP", source: "column", aggs: ["countDistinct"] },
  { key: "dstPort", label: "独立目的端口", source: "column", aggs: ["countDistinct"] },
  { key: "srcPort", label: "独立源端口", source: "column", aggs: ["countDistinct"] },
  { key: "dnsQueryName", label: "独立域名", source: "meta", aggs: ["countDistinct"] },
];

export const AGG_LABEL: Record<AggFn, string> = {
  count: "计数", sum: "求和", avg: "均值", max: "最大值", min: "最小值", countDistinct: "去重计数",
};

export const OP_LABEL: Record<FilterOp, string> = {
  eq: "=", ne: "≠", gt: ">", gte: "≥", lt: "<", lte: "≤", like: "包含",
};

export interface MetricDef {
  field: string;
  agg: AggFn;
  alias: string;
}

export interface FilterDef {
  field: string;
  op: FilterOp;
  value: string;
}

export interface HavingDef {
  metricIndex: number;
  op: FilterOp;
  value: number;
}

export interface ModelDef {
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  dimensions: string[];
  metrics: MetricDef[];
  filters: FilterDef[];
  having: HavingDef | null;
}

/** 建模五步流程（前端向导展示用） */
export const MODELING_STEPS = [
  { no: 1, title: "定义模型", desc: "名称、用途与告警级别" },
  { no: 2, title: "选择维度", desc: "从字段库选择分组维度（GROUP BY）" },
  { no: 3, title: "配置度量", desc: "选择度量字段与聚合函数" },
  { no: 4, title: "过滤与阈值", desc: "数据过滤条件与告警触发阈值" },
  { no: 5, title: "运行验证", desc: "保存模型并对全量会话执行分析" },
];
