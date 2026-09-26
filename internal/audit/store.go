package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Loccao102/Agent-Guard/internal/redact"
	_ "modernc.org/sqlite"
)

type Event struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Agent        string    `json:"agent"`
	Kind         string    `json:"kind"`
	Value        string    `json:"value"`
	Decision     string    `json:"decision"`
	Risk         string    `json:"risk"`
	Reason       string    `json:"reason"`
	RuleID       string    `json:"rule_id,omitempty"`
	PreviousHash string    `json:"previous_hash,omitempty"`
	Hash         string    `json:"hash,omitempty"`
}

type Stats struct {
	Total    int64 `json:"total"`
	Allowed  int64 `json:"allowed"`
	Asked    int64 `json:"asked"`
	Denied   int64 `json:"denied"`
	HighRisk int64 `json:"high_risk"`
}

type Verification struct {
	Valid        bool   `json:"valid"`
	Checked      int    `json:"checked"`
	FirstBadID   int64  `json:"first_bad_id,omitempty"`
	Message      string `json:"message"`
	LegacyEvents int    `json:"legacy_events"`
}

type Store struct {
	db       *sql.DB
	redactor redact.Redactor
	mu       sync.Mutex
	lastHash string
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create audit dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	// High-throughput pragmas for 50k-200k event scale
	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA cache_size = -64000;",
		"PRAGMA temp_store = MEMORY;",
	}
	for _, p := range pragmas {
		_, _ = db.Exec(p)
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
		rule_id TEXT NOT NULL DEFAULT '',
		previous_hash TEXT NOT NULL DEFAULT '',
		hash TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_hash_id ON events(hash, id DESC);`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init audit database: %w", err)
	}
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN hash TEXT NOT NULL DEFAULT ''`)

	var lastHash string
	_ = db.QueryRow(`SELECT hash FROM events WHERE hash <> '' ORDER BY id DESC LIMIT 1`).Scan(&lastHash)

	return &Store{
		db:       db,
		redactor: redact.New(),
		lastHash: lastHash,
	}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Record(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	e.Value = s.redactor.String(e.Value)
	e.PreviousHash = s.lastHash
	e.Hash = eventHash(e)

	_, err := s.db.Exec(
		`INSERT INTO events(timestamp,agent,kind,value,decision,risk,reason,rule_id,previous_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.Agent,
		e.Kind,
		e.Value,
		e.Decision,
		e.Risk,
		e.Reason,
		e.RuleID,
		e.PreviousHash,
		e.Hash,
	)
	if err != nil {
		return err
	}
	s.lastHash = e.Hash
	return nil
}

// RecordBatch bulk inserts events in chunks of up to 5,000 per transaction,
// maintaining cryptographic hash-chain continuity.
func (s *Store) RecordBatch(events []Event) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	chunkSize := 5000
	curHash := s.lastHash

	for start := 0; start < len(events); start += chunkSize {
		end := start + chunkSize
		if end > len(events) {
			end = len(events)
		}
		chunk := events[start:end]

		tx, err := s.db.Begin()
		if err != nil {
			return err
		}

		stmt, err := tx.Prepare(`INSERT INTO events(timestamp,agent,kind,value,decision,risk,reason,rule_id,previous_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			return err
		}

		for i := range chunk {
			if chunk[i].Timestamp.IsZero() {
				chunk[i].Timestamp = time.Now().UTC()
			}
			chunk[i].Value = s.redactor.String(chunk[i].Value)
			chunk[i].PreviousHash = curHash
			chunk[i].Hash = eventHash(chunk[i])
			curHash = chunk[i].Hash

			_, err = stmt.Exec(
				chunk[i].Timestamp.UTC().Format(time.RFC3339Nano),
				chunk[i].Agent,
				chunk[i].Kind,
				chunk[i].Value,
				chunk[i].Decision,
				chunk[i].Risk,
				chunk[i].Reason,
				chunk[i].RuleID,
				chunk[i].PreviousHash,
				chunk[i].Hash,
			)
			if err != nil {
				stmt.Close()
				tx.Rollback()
				return err
			}
		}

		stmt.Close()
		if err := tx.Commit(); err != nil {
			return err
		}
		s.lastHash = curHash
	}

	return nil
}

func (s *Store) List(limit int) ([]Event, error) {
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,timestamp,agent,kind,value,decision,risk,reason,rule_id,previous_hash,hash FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Agent, &e.Kind, &e.Value, &e.Decision, &e.Risk, &e.Reason, &e.RuleID, &e.PreviousHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	var total, allowed, asked, denied, high sql.NullInt64
	err := s.db.QueryRow(`SELECT COUNT(*),SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END),SUM(CASE WHEN decision='ask' THEN 1 ELSE 0 END),SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END),SUM(CASE WHEN risk IN ('high','critical') THEN 1 ELSE 0 END) FROM events`).Scan(&total, &allowed, &asked, &denied, &high)
	if err != nil {
		return Stats{}, err
	}
	st.Total, st.Allowed, st.Asked, st.Denied, st.HighRisk = total.Int64, allowed.Int64, asked.Int64, denied.Int64, high.Int64
	return st, nil
}

func (s *Store) Verify() (Verification, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT id,timestamp,agent,kind,value,decision,risk,reason,rule_id,previous_hash,hash FROM events ORDER BY id ASC`)
	if err != nil {
		return Verification{}, err
	}
	defer rows.Close()
	result := Verification{Valid: true, Message: "audit hash chain is valid"}
	previous := ""
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Agent, &e.Kind, &e.Value, &e.Decision, &e.Risk, &e.Reason, &e.RuleID, &e.PreviousHash, &e.Hash); err != nil {
			return Verification{}, err
		}
		if e.Hash == "" {
			result.LegacyEvents++
			continue
		}
		result.Checked++
		expected := computeRawHash(ts, e.Agent, e.Kind, e.Value, e.Decision, e.Risk, e.Reason, e.RuleID, e.PreviousHash)
		if e.PreviousHash != previous || expected != e.Hash {
			result.Valid = false
			result.FirstBadID = e.ID
			result.Message = "audit hash chain verification failed"
			return result, nil
		}
		previous = e.Hash
	}
	if err := rows.Err(); err != nil {
		return Verification{}, err
	}
	if result.Checked == 0 && result.LegacyEvents > 0 {
		result.Message = "no v1 hash-chained events yet; legacy events were skipped"
	}
	return result, nil
}

func computeRawHash(ts, agent, kind, value, decision, risk, reason, ruleID, previousHash string) string {
	parts := []string{ts, agent, kind, value, decision, risk, reason, ruleID, previousHash}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(h[:])
}

func eventHash(e Event) string {
	return computeRawHash(e.Timestamp.UTC().Format(time.RFC3339Nano), e.Agent, e.Kind, e.Value, e.Decision, e.Risk, e.Reason, e.RuleID, e.PreviousHash)
}
