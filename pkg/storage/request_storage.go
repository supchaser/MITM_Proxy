package storage

import (
	"net/http"
	"sync"
	"time"
)

type RequestInfo struct {
	ID        int
	Method    string
	URL       string
	Headers   http.Header
	Body      string
	Timestamp time.Time
}

type RequestStore struct {
	requests []*RequestInfo
	mutex    sync.Mutex
}

func NewRequestStore() *RequestStore {
	return &RequestStore{
		requests: make([]*RequestInfo, 0),
	}
}

func (s *RequestStore) AddRequest(method, fullURL string, headers http.Header, body string) int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id := len(s.requests)
	s.requests = append(s.requests, &RequestInfo{
		ID:        id,
		Method:    method,
		URL:       fullURL,
		Headers:   headers.Clone(),
		Body:      body,
		Timestamp: time.Now(),
	})
	return id
}

func (s *RequestStore) GetRequestByID(id int) *RequestInfo {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if id < 0 || id >= len(s.requests) {
		return nil
	}
	return s.requests[id]
}

func (s *RequestStore) GetAllRequests() []*RequestInfo {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return append([]*RequestInfo(nil), s.requests...)
}
