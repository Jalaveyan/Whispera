package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/nekoskin/whispera/neural"
)

type blockmapStore struct {
	mu      sync.Mutex
	entries map[string]*neural.BlockmapEntry
}

var globalBlockmap = &blockmapStore{entries: make(map[string]*neural.BlockmapEntry)}

func blockmapKey(cc, asn string) string { return cc + "/" + asn }

func (b *blockmapStore) merge(r neural.BlockReport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := blockmapKey(r.CC, r.ASN)
	e := b.entries[key]
	if e == nil {
		e = &neural.BlockmapEntry{CC: r.CC, ASN: r.ASN, Transports: make(map[string]neural.TransportRate)}
		b.entries[key] = e
	}
	for name, rep := range r.Reports {
		cur := e.Transports[name]
		cur.OK += rep.OK
		cur.Fail += rep.Fail
		if tot := cur.OK + cur.Fail; tot > 0 {
			cur.Rate = float64(cur.OK) / float64(tot)
		}
		e.Transports[name] = cur
	}
	e.Pool = e.Pool[:0]
	e.Avoid = e.Avoid[:0]
	for name, tr := range e.Transports {
		if tr.OK+tr.Fail >= 5 && tr.Rate < 0.3 {
			e.Avoid = append(e.Avoid, name)
		} else {
			e.Pool = append(e.Pool, name)
		}
	}
}

func (b *blockmapStore) snapshot(cc, asn string) interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cc != "" {
		return b.entries[blockmapKey(cc, asn)]
	}
	out := make([]*neural.BlockmapEntry, 0, len(b.entries))
	for _, e := range b.entries {
		out = append(out, e)
	}
	return out
}

func handleBlockmapReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var rep neural.BlockReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&rep); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	globalBlockmap.merge(rep)
	w.WriteHeader(http.StatusNoContent)
}

func handleBlockmapQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(globalBlockmap.snapshot(r.URL.Query().Get("cc"), r.URL.Query().Get("asn")))
}
