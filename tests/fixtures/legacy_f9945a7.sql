PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    t REAL NOT NULL,
    wall_time REAL NOT NULL,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    threat_score REAL NOT NULL,
    confidence REAL NOT NULL,
    integrity_status TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    evidence TEXT NOT NULL,
    detector_scores TEXT NOT NULL,
    contributing_detectors TEXT NOT NULL,
    telemetry TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
INSERT INTO events VALUES(1,'legacy-run',1.0,1700000001.0,'GPS_SPOOFING','HIGH',0.72,0.85,'VALID',0.42,'["legacy gps mismatch"]','{"PHYSICS": 0.72}','["PHYSICS"]','{"lat": 12.9, "lon": 77.5}','0000000000000000000000000000000000000000000000000000000000000000','90e6d1fdeca0659a75bc13af19c4f88e9e9f583636e87a409bf7e489fd063c3a');
INSERT INTO events VALUES(2,'legacy-run',2.0,1700000002.0,'GPS_SPOOFING','HIGH',0.88,0.85,'VALID',0.42,'["legacy gps mismatch"]','{"PHYSICS": 0.88}','["PHYSICS"]','{"lat": 12.9, "lon": 77.5}','90e6d1fdeca0659a75bc13af19c4f88e9e9f583636e87a409bf7e489fd063c3a','5b9f70b7b338504c6bde1beb66e0849e39320c3ab8c15a6c85b9e0e6898e3d6c');
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    started REAL NOT NULL,
    label TEXT,
    meta TEXT
);
INSERT INTO runs VALUES('legacy-run',1700000000.0,'sim','{}');
PRAGMA writable_schema=ON;
CREATE TABLE IF NOT EXISTS sqlite_sequence(name,seq);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('events',2);
CREATE INDEX idx_events_run ON events(run_id);
CREATE INDEX idx_events_t ON events(t);
PRAGMA writable_schema=OFF;
COMMIT;
