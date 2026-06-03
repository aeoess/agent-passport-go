// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

// Package keystore mirrors the reference SDK key-storage backend interface
// (src/crypto/key-storage.ts). InMemoryKeyStorage holds keys in process memory
// only. As in the reference SDK, the in-memory backend stores raw hex; it is for
// development and testing, not durable at-rest storage.
package keystore

import (
	"errors"
	"sort"
	"sync"
)

// KeyStorageBackend stores and retrieves agent keypairs. Methods return errors
// instead of the reference SDK's Promise rejections.
type KeyStorageBackend interface {
	Store(agentID, privateKey, publicKey string) error
	Retrieve(agentID string) (record *KeyRecord, err error)
	Delete(agentID string) (bool, error)
	List() ([]string, error)
}

// KeyRecord is a stored keypair. A nil *KeyRecord from Retrieve means not found.
type KeyRecord struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

// InMemoryKeyStorage is a process-memory KeyStorageBackend. Safe for concurrent
// use.
type InMemoryKeyStorage struct {
	mu   sync.RWMutex
	keys map[string]KeyRecord
}

// NewInMemoryKeyStorage returns an empty in-memory backend.
func NewInMemoryKeyStorage() *InMemoryKeyStorage {
	return &InMemoryKeyStorage{keys: map[string]KeyRecord{}}
}

var errEmptyAgentID = errors.New("keystore: agentID must be non-empty")

func (s *InMemoryKeyStorage) Store(agentID, privateKey, publicKey string) error {
	if agentID == "" {
		return errEmptyAgentID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[agentID] = KeyRecord{PrivateKey: privateKey, PublicKey: publicKey}
	return nil
}

func (s *InMemoryKeyStorage) Retrieve(agentID string) (*KeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.keys[agentID]
	if !ok {
		return nil, nil
	}
	cp := rec
	return &cp, nil
}

func (s *InMemoryKeyStorage) Delete(agentID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[agentID]; !ok {
		return false, nil
	}
	delete(s.keys, agentID)
	return true, nil
}

func (s *InMemoryKeyStorage) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
