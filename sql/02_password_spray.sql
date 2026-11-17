-- Password spraying (T1110.003)
-- One address failing against 15 or more different accounts in the same hour.
-- A real user mistypes their own password. They don't mistype fifteen other people's.

WITH per_hour AS (
    SELECT src_ip,
           ts_epoch / 3600                AS hour_bucket,
           COUNT(DISTINCT username)       AS accounts_failed
    FROM events
    WHERE result = 'FAIL' AND ts_epoch >= :detect_from
    GROUP BY src_ip, ts_epoch / 3600
),
sprayers AS (
    SELECT src_ip, MIN(hour_bucket) AS first_hour, MAX(hour_bucket) AS last_hour
    FROM per_hour
    WHERE accounts_failed >= 15
    GROUP BY src_ip
)
SELECT e.event_id,
       'password_spray' AS detector,
       s.src_ip         AS alert_key
FROM events e
JOIN sprayers s ON s.src_ip = e.src_ip
WHERE e.ts_epoch / 3600 BETWEEN s.first_hour - 1 AND s.last_hour + 1;
