package audit

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Event struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Agent     string    `json:"agent"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Decision  string    `json:"decision"`
	Risk      string    `json:"risk"`
	Reason    string    `json:"reason"`
	RuleID    string    `json:"rule_id,omitempty"`
}

type Stats struct {
	Total   int64 `json:"total"`
	Allowed int64 `json:"allowed"`
	Asked   int64 `json:"asked"`
	Denied  int64 `json:"denied"`
	HighRisk int64 `json:"high_risk"`
}

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create audit dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		agent TEXT NOT NULL,
		kind TEXT NOT NULL,
		value TEXT NOT NULL,
		decision TEXT NOT NULL,
		risk TEXT NOT NULL,
		reason TEXT NOT NULL,
		rule_id TEXT NOT NULL DEFAULT ''
	); CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init audit database: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Record(e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	_, err := s.db.Exec(`INSERT INTO events(timestamp,agent,kind,value,decision,risk,reason,rule_id) VALUES(?,?,?,?,?,?,?,?)`,
		e.Timestamp.Format(time.RFC3339Nano), e.Agent, e.Kind, e.Value, e.Decision, e.Risk, e.Reason, e.RuleID)
	return err
}

func (s *Store) List(limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,timestamp,agent,kind,value,decision,risk,reason,rule_id FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Agent, &e.Kind, &e.Value, &e.Decision, &e.Risk, &e.Reason, &e.RuleID); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	err := s.db.QueryRow(`SELECT
		COUNT(*),
		SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END),
		SUM(CASE WHEN decision='ask' THEN 1 ELSE 0 END),
		SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END),
		SUM(CASE WHEN risk IN ('high','critical') THEN 1 ELSE 0 END)
		FROM events`).Scan(&st.Total, &st.Allowed, &st.Asked, &st.Denied, &st.HighRisk)
	if err != nil {
		return Stats{}, err
	}
	return st, nil
}
