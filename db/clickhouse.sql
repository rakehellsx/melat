CREATE TABLE IF NOT EXISTS sessions (
 id UInt64, session_id String, src_ip String, src_port UInt32, dst_ip String, dst_port UInt32,
 protocol LowCardinality(String), app_protocol LowCardinality(String), direction LowCardinality(String),
 start_time DateTime64(3, 'UTC'), duration Int64 DEFAULT 0,
 up_packets UInt64 DEFAULT 0, down_packets UInt64 DEFAULT 0,
 up_bytes UInt64 DEFAULT 0, down_bytes UInt64 DEFAULT 0,
 dst_country Nullable(String), threat_score Int32 DEFAULT 0, meta String,
 created_at DateTime64(3, 'UTC') DEFAULT now64(3), ingest_batch_id Nullable(UInt64),
 INDEX batch_index ifNull(ingest_batch_id,0) TYPE minmax GRANULARITY 1,
 INDEX src_index src_ip TYPE bloom_filter GRANULARITY 4,
 INDEX dst_index dst_ip TYPE bloom_filter GRANULARITY 4
) ENGINE=MergeTree ORDER BY (start_time,id) SETTINGS index_granularity=8192;
CREATE TABLE IF NOT EXISTS analysis_runs (
 id UInt64, rule_code String, status String DEFAULT 'running', sessions_scanned UInt64 DEFAULT 0,
 alerts_generated UInt64 DEFAULT 0, duration_ms UInt64 DEFAULT 0,
 started_at DateTime64(3, 'UTC') DEFAULT now64(3), finished_at Nullable(DateTime64(3, 'UTC'))
) ENGINE=MergeTree ORDER BY id;
CREATE TABLE IF NOT EXISTS alerts (
 id UInt64, rule_code String, rule_name String, category LowCardinality(String), severity LowCardinality(String),
 title String, src_ip Nullable(String), dst_ip Nullable(String), score Int32 DEFAULT 0,
 evidence String, related_sessions String, status String DEFAULT 'open', run_id Nullable(UInt64),
 created_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE=MergeTree ORDER BY id;
CREATE TABLE IF NOT EXISTS ingest_batches (
 id UInt64, filename String, size_bytes UInt64 DEFAULT 0, packets UInt64 DEFAULT 0,
 flows UInt64 DEFAULT 0, skipped UInt64 DEFAULT 0, duration_ms UInt64 DEFAULT 0,
 created_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE=MergeTree ORDER BY id;
CREATE TABLE IF NOT EXISTS custom_models (
 id UInt64, name String, description String DEFAULT '', severity String DEFAULT 'medium',
 dimensions String, metrics String, filters String, having_def Nullable(String),
 created_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE=MergeTree ORDER BY id;
CREATE TABLE IF NOT EXISTS ingest_jobs (
 id String, filename String, size_bytes UInt64, status String DEFAULT 'queued',
 packets UInt64 DEFAULT 0, imported UInt64 DEFAULT 0, batch_id Nullable(UInt64),
 result Nullable(String), error Nullable(String),
 created_at DateTime64(3, 'UTC') DEFAULT now64(3), updated_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE=MergeTree ORDER BY id;
