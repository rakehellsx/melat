import { FIELD_CATEGORIES, type FieldType } from "./fields";

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
  type?: FieldType;
  category?: string;
}

export interface MetricFieldDef {
  key: string;
  label: string;
  source: "column" | "meta" | "computed";
  aggs: AggFn[];
  category?: string;
  type?: FieldType;
}

/** All catalog fields are shared by grouping, metrics, and filtering. */
const COLUMN_KEYS = new Set(["sessionId", "srcIp", "srcPort", "dstIp", "dstPort", "protocol", "appProtocol", "direction", "dstCountry", "startTime", "upBytes", "downBytes", "upPackets", "downPackets", "duration", "threatScore"]);
const NUMERIC_TYPES = new Set(["number", "port", "ratio", "boolean"]);
export const DIMENSIONS: DimensionDef[] = FIELD_CATEGORIES.flatMap(category =>
  category.fields.map(field => ({ key: field.key, label: field.label,
    source: COLUMN_KEYS.has(field.key) ? "column" as const : "meta" as const,
    type: field.type, category: category.label, numeric: NUMERIC_TYPES.has(field.type) })),
);
export const METRIC_FIELDS: MetricFieldDef[] = [
  { key: "*", label: "会话数", source: "column", aggs: ["count"], category: "基础统计" },
  { key: "threatScore", label: "威胁评分", source: "column", type: "number", aggs: ["count", "countDistinct", "sum", "avg", "max", "min"], category: "基础统计" },
  ...DIMENSIONS.map(field => ({ key: field.key, label: field.label, source: field.source,
    category: field.category, type: field.type,
    aggs: (field.numeric ? ["count", "countDistinct", "sum", "avg", "max", "min"] : ["count", "countDistinct"]) as AggFn[] })),
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
