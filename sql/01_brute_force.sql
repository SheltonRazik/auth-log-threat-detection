-- Brute force (MITRE ATT&CK T1110.001, password guessing)
-- One address failing against one account 20 or more times inside any 10 minutes.
-- The window slides with each event, so an attack can't hide by straddling a clock boundary.
-- Every event for that address + account pair is returned, including a success if the guess worked.

WITH fails AS (
    SELECT src_ip, username,
           COUNT(*) OVER (
               PARTITION BY src_ip, username
               ORDER BY ts_epoch
               RANGE BETWEEN 600 PRECEDING AND CURRENT ROW
           ) AS fails_10m
    FROM events
    WHERE result = 'FAIL' AND ts_epoch >= :detect_from
),
hot AS (
    SELECT DISTINCT src_ip, username FROM fails WHERE fails_10m >= 20
)
SELECT e.event_id,
       'brute_force'                   AS detector,
       h.src_ip || ' > ' || h.username AS alert_key
FROM events e
JOIN hot h ON h.src_ip = e.src_ip AND h.username = e.username
WHERE e.ts_epoch >= :detect_from;
