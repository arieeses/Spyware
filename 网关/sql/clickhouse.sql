CREATE DATABASE IF NOT EXISTS sub_gateway;

CREATE TABLE IF NOT EXISTS sub_gateway.subscription_access_events
(
  event_date Date DEFAULT toDate(ts),
  ts DateTime64(3),
  tenant_id LowCardinality(String),
  host LowCardinality(String),
  origin_base_url String,
  token_raw String,
  token_hash FixedString(64),
  client_ip String,
  remote_addr String,
  decision LowCardinality(String),
  risk_reason LowCardinality(String),
  risk_level UInt8,
  is_suspicious UInt8,
  flag LowCardinality(String),
  client_type LowCardinality(String),
  user_agent String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (tenant_id, token_hash, client_ip, ts)
TTL event_date + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS sub_gateway.ip_token_edges
(
  event_date Date,
  tenant_id LowCardinality(String),
  token_hash FixedString(64),
  client_ip String,
  first_seen AggregateFunction(min, DateTime64(3)),
  last_seen AggregateFunction(max, DateTime64(3)),
  hit_count AggregateFunction(count),
  suspicious_count AggregateFunction(sum, UInt8)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(event_date)
ORDER BY (event_date, tenant_id, token_hash, client_ip)
TTL event_date + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS sub_gateway.mv_ip_token_edges
TO sub_gateway.ip_token_edges AS
SELECT
  event_date,
  tenant_id,
  token_hash,
  client_ip,
  minState(ts) AS first_seen,
  maxState(ts) AS last_seen,
  countState() AS hit_count,
  sumState(is_suspicious) AS suspicious_count
FROM sub_gateway.subscription_access_events
GROUP BY event_date, tenant_id, token_hash, client_ip;

CREATE TABLE IF NOT EXISTS sub_gateway.global_suspicious_ips
(
  ip_or_cidr String,
  reason LowCardinality(String),
  note String,
  added_by String,
  added_at DateTime64(3),
  expires_at Nullable(DateTime64(3)),
  enabled UInt8
)
ENGINE = MergeTree
ORDER BY (enabled, ip_or_cidr, added_at)
TTL toDate(added_at) + INTERVAL 365 DAY;
