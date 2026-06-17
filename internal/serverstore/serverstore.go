// Package serverstore persists the list of VPN servers the user manages for
// redundancy. It mirrors the tiny atomic-JSON pattern of internal/store. It NEVER
// stores SSH credentials — only the reachable address, user, and what was set up.
package serverstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"wakeroute/internal/atomicfile"
)

// Server is one managed VPN server. No password/key is ever persisted here.
type Server struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Port      int      `json:"port"`
	User      string   `json:"user"`
	Installed []string `json:"installed"` // protocol ids provisioned on it
	Hardened  bool     `json:"hardened"`  // password auth disabled + key installed
	Note      string   `json:"note,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	LastJob   string   `json:"last_job,omitempty"` // most recent job id
}

// Store guards the server list persisted at path.
type Store struct {
	path string
	mu   sync.RWMutex
	srv  []Server
}

// Open loads servers.json, creating an empty list if absent.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read servers %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.srv); err != nil {
		return nil, fmt.Errorf("parse servers %s: %w", path, err)
	}
	return s, nil
}

// List returns a copy of the server list. Each Server's Installed slice is
// deep-cloned: a shallow copy aliases the backing array, which a lock-free reader
// (e.g. the GET /servers handler marshalling the result) would race if a writer
// later mutates Installed in place. Mirrors store.Profile()'s defensive cloning.
func (s *Store) List() []Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Server, len(s.srv))
	copy(out, s.srv)
	for i := range out {
		out[i].Installed = append([]string(nil), out[i].Installed...)
	}
	return out
}

// Get returns a server by id, with its Installed slice cloned (see List).
func (s *Store) Get(id string) (Server, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sv := range s.srv {
		if sv.ID == id {
			sv.Installed = append([]string(nil), sv.Installed...)
			return sv, true
		}
	}
	return Server{}, false
}

// Upsert inserts or replaces a server by ID (ID is required).
func (s *Store) Upsert(sv Server) error {
	if sv.ID == "" {
		return errors.New("server id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.srv {
		if s.srv[i].ID == sv.ID {
			s.srv[i] = sv
			return s.saveLocked()
		}
	}
	s.srv = append(s.srv, sv)
	return s.saveLocked()
}

// Patch applies fn to the stored server with id (if present) and persists.
func (s *Store) Patch(id string, fn func(*Server)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.srv {
		if s.srv[i].ID == id {
			fn(&s.srv[i])
			return s.saveLocked()
		}
	}
	return fmt.Errorf("server %q not found", id)
}

// Delete removes a server by id.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.srv[:0]
	found := false
	for _, sv := range s.srv {
		if sv.ID == id {
			found = true
			continue
		}
		out = append(out, sv)
	}
	if !found {
		return fmt.Errorf("server %q not found", id)
	}
	s.srv = out
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return errors.New("server store has no path")
	}
	data, err := json.MarshalIndent(s.srv, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(s.path, data, 0o600)
}
