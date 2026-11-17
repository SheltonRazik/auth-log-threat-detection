-- Impossible travel (T1078, valid accounts)
-- Two successful logins by the same account from different countries, closer together in
-- time than a plane could cover the distance. 900 km/h is about airliner cruising speed.
-- This catches stolen passwords, where there are no failed logins to see.

WITH logins AS (
    SELECT event_id, username, country, ts_epoch,
           LAG(country)  OVER (PARTITION BY username ORDER BY ts_epoch) AS prev_country,
           LAG(ts_epoch) OVER (PARTITION BY username ORDER BY ts_epoch) AS prev_epoch
    FROM events
    WHERE result = 'SUCCESS'
)
SELECT l.event_id,
       'impossible_travel' AS detector,
       l.username || ' ' || l.prev_country || '>' || l.country AS alert_key
FROM logins l
JOIN country_distance d ON d.country_a = l.prev_country AND d.country_b = l.country
WHERE l.ts_epoch >= :detect_from
  AND l.country <> l.prev_country
  AND d.km / (MAX(l.ts_epoch - l.prev_epoch, 1) / 3600.0) > 900;
