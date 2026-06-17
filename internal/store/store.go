// Package store persists the user Profile (endpoints/groups/rules) to a JSON
// file and offers thread-safe CRUD. It is intentionally tiny: no database, a
// single atomically-written file under /opt/etc/wakeroute/ (see docs/ARCHITECTURE.md).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"wakeroute/internal/atomicfile"
	"wakeroute/internal/model"
)

// Store guards a Profile persisted at path.
type Store struct {
	path string
	mu   sync.RWMutex
	prof model.Profile
}

// Open loads the profile at path, creating an empty one if it does not exist.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.prof); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}
	return s, nil
}

// Profile returns a copy of the current profile with its three slices cloned, so
// a caller can iterate them after the lock is released while a concurrent writer
// mutates (replaces/compacts) the store's backing arrays. A plain value copy
// would alias those arrays — a data race. Endpoint/Group/Rule values are
// immutable once stored (writers replace whole elements, never mutate in place),
// so cloning the top-level slices is sufficient.
func (s *Store) Profile() model.Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.prof
	p.Endpoints = append([]model.Endpoint(nil), s.prof.Endpoints...)
	p.Groups = append([]model.Group(nil), s.prof.Groups...)
	// Group.Members is compacted IN PLACE by removeString (DeleteEndpoint/DeleteGroup
	// pruning), so it must be cloned too — a shallow Group copy still aliases the
	// members backing array, which a lock-free reader (generator/monitor) would race.
	for i := range p.Groups {
		p.Groups[i].Members = append([]string(nil), s.prof.Groups[i].Members...)
	}
	p.Rules = append([]model.Rule(nil), s.prof.Rules...)
	// RoutingLists is compacted IN PLACE by DeleteRoutingList (kept[:0]) and may be
	// appended to by UpsertRoutingList, so a shallow copy would alias the backing
	// array a lock-free reader (generator) races on — clone it like the others.
	p.RoutingLists = append([]model.RoutingList(nil), s.prof.RoutingLists...)
	return p
}

// Replace swaps the whole profile (used by bulk import / subscription sync).
func (s *Store) Replace(p model.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prof = p
	return s.saveLocked()
}

// UpsertEndpoint inserts or replaces an endpoint by ID.
func (s *Store) UpsertEndpoint(e model.Endpoint) error {
	if e.ID == "" {
		return errors.New("endpoint id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.prof.Endpoints {
		if s.prof.Endpoints[i].ID == e.ID {
			s.prof.Endpoints[i] = e
			return s.saveLocked()
		}
	}
	s.prof.Endpoints = append(s.prof.Endpoints, e)
	return s.saveLocked()
}

// DeleteEndpoint removes an endpoint, pruning it from group members. It refuses
// if a rule still targets the endpoint (the caller should repoint the rule first).
func (s *Store) DeleteEndpoint(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.prof.Rules {
		if r.Outbound == id {
			return fmt.Errorf("endpoint %q is used by rule %q; repoint it first", id, r.ID)
		}
	}
	// Refuse if this endpoint is the sole member of a group — pruning it would
	// leave a zero-member group, which fails Validate() and blocks every Apply.
	for _, g := range s.prof.Groups {
		if onlyMember(g.Members, id) {
			return fmt.Errorf("endpoint %q is the only member of group %q; remove or repoint that group first", id, g.ID)
		}
	}
	// Refuse if a routing list routes (or downloads) via this endpoint — a dangling
	// outbound fails Validate() and blocks every Apply (same intent as the rule guard).
	for _, rl := range s.prof.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			return fmt.Errorf("endpoint %q is used by routing list %q (route/download via); repoint it first", id, rl.ID)
		}
	}
	kept := s.prof.Endpoints[:0]
	found := false
	for _, e := range s.prof.Endpoints {
		if e.ID == id {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("endpoint %q not found", id)
	}
	s.prof.Endpoints = kept
	for gi := range s.prof.Groups {
		s.prof.Groups[gi].Members = removeString(s.prof.Groups[gi].Members, id)
	}
	return s.saveLocked()
}

// UpsertGroup inserts or replaces a group by ID.
func (s *Store) UpsertGroup(g model.Group) error {
	if g.ID == "" {
		return errors.New("group id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.prof.Groups {
		if s.prof.Groups[i].ID == g.ID {
			s.prof.Groups[i] = g
			return s.saveLocked()
		}
	}
	s.prof.Groups = append(s.prof.Groups, g)
	return s.saveLocked()
}

// DeleteGroup removes a group; refuses if a rule targets it.
func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.prof.Rules {
		if r.Outbound == id {
			return fmt.Errorf("group %q is used by rule %q; repoint it first", id, r.ID)
		}
	}
	// Refuse if this group is the sole member of another group (nested groups) —
	// pruning it would leave that parent empty and fail Validate().
	for _, g := range s.prof.Groups {
		if g.ID != id && onlyMember(g.Members, id) {
			return fmt.Errorf("group %q is the only member of group %q; remove or repoint that group first", id, g.ID)
		}
	}
	// Refuse if a routing list routes (or downloads) via this group — see DeleteEndpoint.
	for _, rl := range s.prof.RoutingLists {
		if rl.Outbound == id || rl.DownloadVia == id {
			return fmt.Errorf("group %q is used by routing list %q (route/download via); repoint it first", id, rl.ID)
		}
	}
	kept := s.prof.Groups[:0]
	found := false
	for _, g := range s.prof.Groups {
		if g.ID == id {
			found = true
			continue
		}
		kept = append(kept, g)
	}
	if !found {
		return fmt.Errorf("group %q not found", id)
	}
	s.prof.Groups = kept
	// Mirror DeleteEndpoint: prune the deleted group's id from any group that
	// listed it as a nested member, so the profile stays Validate-clean.
	for gi := range s.prof.Groups {
		s.prof.Groups[gi].Members = removeString(s.prof.Groups[gi].Members, id)
	}
	return s.saveLocked()
}

// onlyMember reports whether id is in members and every member equals id, so
// removing id would empty the slice.
func onlyMember(members []string, id string) bool {
	if len(members) == 0 {
		return false
	}
	for _, m := range members {
		if m != id {
			return false
		}
	}
	return true
}

// UpsertRule inserts or replaces a rule by ID.
func (s *Store) UpsertRule(r model.Rule) error {
	if r.ID == "" {
		return errors.New("rule id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.prof.Rules {
		if s.prof.Rules[i].ID == r.ID {
			s.prof.Rules[i] = r
			return s.saveLocked()
		}
	}
	s.prof.Rules = append(s.prof.Rules, r)
	return s.saveLocked()
}

// DeleteRule removes a rule by ID.
func (s *Store) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.prof.Rules[:0]
	found := false
	for _, r := range s.prof.Rules {
		if r.ID == id {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return fmt.Errorf("rule %q not found", id)
	}
	s.prof.Rules = kept
	return s.saveLocked()
}

// UpsertRoutingList inserts or replaces a routing list by ID.
func (s *Store) UpsertRoutingList(rl model.RoutingList) error {
	if rl.ID == "" {
		return errors.New("routing list id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.prof.RoutingLists {
		if s.prof.RoutingLists[i].ID == rl.ID {
			s.prof.RoutingLists[i] = rl
			return s.saveLocked()
		}
	}
	s.prof.RoutingLists = append(s.prof.RoutingLists, rl)
	return s.saveLocked()
}

// DeleteRoutingList removes a routing list by ID.
func (s *Store) DeleteRoutingList(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.prof.RoutingLists[:0]
	found := false
	for _, rl := range s.prof.RoutingLists {
		if rl.ID == id {
			found = true
			continue
		}
		kept = append(kept, rl)
	}
	if !found {
		return fmt.Errorf("routing list %q not found", id)
	}
	s.prof.RoutingLists = kept
	return s.saveLocked()
}

// saveLocked atomically + durably writes the profile. Callers must hold s.mu (write).
func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.prof, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o600)
}

func removeString(ss []string, target string) []string {
	out := ss[:0]
	for _, s := range ss {
		if s != target {
			out = append(out, s)
		}
	}
	return out
}
