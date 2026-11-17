DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS country_distance;

CREATE TABLE events (
    event_id  TEXT PRIMARY KEY,
    ts        TEXT NOT NULL,
    ts_epoch  INTEGER NOT NULL,     -- seconds, so time windows are simple arithmetic
    username  TEXT NOT NULL,
    src_ip    TEXT NOT NULL,
    country   TEXT NOT NULL,
    result    TEXT NOT NULL CHECK (result IN ('SUCCESS', 'FAIL'))
);
CREATE INDEX idx_events_user ON events (username, ts_epoch);
CREATE INDEX idx_events_ip ON events (src_ip, ts_epoch);

CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    home_country  TEXT NOT NULL,
    is_admin      INTEGER NOT NULL
);

-- distance between country centre points, filled in by Python
CREATE TABLE country_distance (
    country_a  TEXT NOT NULL,
    country_b  TEXT NOT NULL,
    km         REAL NOT NULL,
    PRIMARY KEY (country_a, country_b)
);
