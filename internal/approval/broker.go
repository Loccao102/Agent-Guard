package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("approval not found")
	ErrExpired  = errors.New("approval expired")
)

type Request struct {
	ID        string    `json:"id"`
	Agent     string    `json:"agent"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Risk      string    `json:"risk"`
	Reason    string    `json:"reason"`
	RuleID    string    `json:"rule_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Resolution struct {
	Decision   string    `json:"decision"`
	Remember   bool      `json:"remember"`
	ResolvedAt time.Time `json:"resolved_at"`
}

type entry struct {
	request  Request
	resolved *Resolution
	notify   chan struct{}
}

type Broker struct {
	mu      sync.Mutex
	pending map[string]*entry
	grants  map[string]struct{}
	ttl     time.Duration
}

func New(ttl time.Duration) *Broker {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &Broker{
		pending: make(map[string]*entry),
		grants:  make(map[string]struct{}),
		ttl:     ttl,
	}
}

func (b *Broker) Create(agent, kind, value, risk, reason, ruleID string) (Request, error) {
	id, err := randomID()
	if err != nil {
		return Request{}, err
	}
	now := time.Now().UTC()
	req := Request{
		ID: id, Agent: agent, Kind: kind, Value: value, Risk: risk,
		Reason: reason, RuleID: ruleID, CreatedAt: now, ExpiresAt: now.Add(b.ttl),
	}

	b.mu.Lock()
	b.cleanupLocked(now)
	b.pending[id] = &entry{request: req, notify: make(chan struct{})}
	b.mu.Unlock()
	return req, nil
}

func (b *Broker) Resolve(id, decision string, remember bool) error {
	if decision != "allow" && decision != "deny" {
		return fmt.Errorf("invalid approval decision %q", decision)
	}

	now := time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupLocked(now)

	e, ok := b.pending[id]
	if !ok || e.resolved != nil {
		return ErrNotFound
	}

	res := Resolution{
		Decision:   decision,
		Remember:   remember && decision == "allow",
		ResolvedAt: now,
	}
	e.resolved = &res
	if res.Remember {
		b.grants[grantKey(e.request.Agent, e.request.Kind, e.request.Value)] = struct{}{}
	}
	close(e.notify)
	return nil
}

func (b *Broker) Wait(ctx context.Context, id string) (Resolution, error) {
	b.mu.Lock()
	b.cleanupLocked(time.Now().UTC())
	e, ok := b.pending[id]
	if !ok {
		b.mu.Unlock()
		return Resolution{}, ErrNotFound
	}
	if e.resolved != nil {
		res := *e.resolved
		delete(b.pending, id)
		b.mu.Unlock()
		return res, nil
	}
	expires := e.request.ExpiresAt
	notify := e.notify
	b.mu.Unlock()

	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()

	select {
	case <-ctx.Done():
		b.remove(id)
		return Resolution{}, ctx.Err()
	case <-timer.C:
		b.remove(id)
		return Resolution{}, ErrExpired
	case <-notify:
		b.mu.Lock()
		defer b.mu.Unlock()
		e, ok := b.pending[id]
		if !ok || e.resolved == nil {
			return Resolution{}, ErrExpired
		}
		res := *e.resolved
		delete(b.pending, id)
		return res, nil
	}
}

func (b *Broker) List() []Request {
	now := time.Now().UTC()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cleanupLocked(now)

	out := make([]Request, 0, len(b.pending))
	for _, e := range b.pending {
		if e.resolved == nil {
			out = append(out, e.request)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

func (b *Broker) HasGrant(agent, kind, value string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.grants[grantKey(agent, kind, value)]
	return ok
}

func (b *Broker) RevokeSessionGrants() {
	b.mu.Lock()
	b.grants = make(map[string]struct{})
	b.mu.Unlock()
}

func (b *Broker) remove(id string) {
	b.mu.Lock()
	delete(b.pending, id)
	b.mu.Unlock()
}

func (b *Broker) cleanupLocked(now time.Time) {
	for id, e := range b.pending {
		if e.request.ExpiresAt.After(now) {
			continue
		}
		delete(b.pending, id)
		if e.resolved == nil {
			close(e.notify)
		}
	}
}

func grantKey(agent, kind, value string) string {
	return agent + "\x00" + kind + "\x00" + value
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate approval id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
