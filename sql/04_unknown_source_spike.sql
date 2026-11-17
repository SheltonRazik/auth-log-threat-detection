-- Slow credential stuffing (T1110.004)
-- The attacker rotates through many addresses and uses each one only a couple of times,
-- so no single address ever looks bad. Rules 1 and 2 are blind to it.
--
-- Instead of looking at one address, look at all "unknown" addresses together. An address is
-- known if anyone logged in from it successfully during the baseline period. Then count how many
-- different accounts had a failed login from unknown addresses in each hour, and compare that
-- with the same count during the baseline.
--
-- An hour is flagged if the count is at least 5 and more than 4 standard deviations above
-- the baseline mean. (Compared as squares because SQLite has no square root by default.)

WITH known_ips AS (
    SELECT DISTINCT src_ip FROM events WHERE result = 'SUCCESS' AND ts_epoch < :detect_from
),
unknown_fails AS (
    SELECT e.event_id, e.ts_epoch / 3600 AS hour_bucket, e.username, e.ts_epoch
    FROM events e
    LEFT JOIN known_ips k ON k.src_ip = e.src_ip
    WHERE e.result = 'FAIL' AND k.src_ip IS NULL
),
all_hours AS (
    SELECT DISTINCT ts_epoch / 3600 AS hour_bucket FROM events
),
hourly AS (
    SELECT h.hour_bucket, COUNT(DISTINCT u.username) AS accounts
    FROM all_hours h
    LEFT JOIN unknown_fails u ON u.hour_bucket = h.hour_bucket
    GROUP BY h.hour_bucket
),
baseline AS (
    SELECT AVG(accounts) AS mean_accounts,
           AVG(accounts * accounts) - AVG(accounts) * AVG(accounts) AS var_accounts
    FROM hourly
    WHERE hour_bucket < :detect_from / 3600
),
flagged_hours AS (
    SELECT h.hour_bucket
    FROM hourly h, baseline b
    WHERE h.hour_bucket >= :detect_from / 3600
      AND h.accounts >= 5
      AND (h.accounts - b.mean_accounts) * (h.accounts - b.mean_accounts) > 16 * b.var_accounts
)
SELECT u.event_id,
       'unknown_source_spike' AS detector,
       date(u.ts_epoch, 'unixepoch') AS alert_key
FROM unknown_fails u
JOIN flagged_hours f ON f.hour_bucket = u.hour_bucket;
