DROP VIEW IF EXISTS sub_gateway.mv_ip_token_edges;

DROP TABLE IF EXISTS sub_gateway.ip_token_edges;

CREATE TABLE sub_gateway.ip_token_edges
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

CREATE MATERIALIZED VIEW sub_gateway.mv_ip_token_edges
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

INSERT INTO sub_gateway.ip_token_edges
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
WHERE event_date >= today() - INTERVAL 30 DAY
GROUP BY event_date, tenant_id, token_hash, client_ip;
