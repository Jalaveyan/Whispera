package mlserver

import (
	"encoding/json"
	"github.com/nekoskin/whispera/neural"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func bmKey(cc, asn string) string { return cc + "|" + asn }

func (s *MLServer) loadBlockmap() {
	data, err := os.ReadFile(filepath.Join(s.fedDir, "blockmap.json"))
	if err != nil {
		return
	}
	var m map[string]*neural.BlockmapEntry
	if json.Unmarshal(data, &m) == nil && m != nil {
		s.blockmapMu.Lock()
		s.blockmap = m
		s.blockmapMu.Unlock()
	}
}

func (s *MLServer) saveBlockmapLocked() {
	data, err := json.Marshal(s.blockmap)
	if err != nil {
		return
	}
	os.MkdirAll(s.fedDir, 0700)
	os.WriteFile(filepath.Join(s.fedDir, "blockmap.json"), data, 0600)
}

func (s *MLServer) handleBlockReport(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1*1024*1024))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var rep neural.BlockReport
	if err := json.Unmarshal(body, &rep); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	key := bmKey(rep.CC, rep.ASN)
	s.blockmapMu.Lock()
	e := s.blockmap[key]
	if e == nil {
		e = &neural.BlockmapEntry{CC: rep.CC, ASN: rep.ASN, Transports: make(map[string]neural.TransportRate)}
		s.blockmap[key] = e
	}
	for name, rr := range rep.Reports {
		cur := e.Transports[name]
		cur.OK += rr.OK
		cur.Fail += rr.Fail
		if tot := cur.OK + cur.Fail; tot > 0 {
			cur.Rate = float64(cur.OK) / float64(tot)
		}
		e.Transports[name] = cur
	}
	s.saveBlockmapLocked()
	s.blockmapMu.Unlock()
	s.addLogf("blockreport: %s — %d transports", key, len(rep.Reports))
	s.jsonReply(w, map[string]interface{}{"ok": true})
}

func (s *MLServer) handleBlockmap(w http.ResponseWriter, r *http.Request) {
	cc := r.URL.Query().Get("cc")
	key := bmKey(cc, r.URL.Query().Get("asn"))
	s.blockmapMu.Lock()
	var out neural.BlockmapEntry
	if e := s.blockmap[key]; e != nil {
		out = *e
		out.Transports = make(map[string]neural.TransportRate, len(e.Transports))
		for k, v := range e.Transports {
			out.Transports[k] = v
		}
	}
	if oc, ok := s.ooniByCC[cc]; ok {
		out.OONI = oc
	}
	s.blockmapMu.Unlock()
	out.Pool, out.Avoid = deriveBlockmapPool(out.Transports, out.OONI)
	s.jsonReply(w, out)
}

func deriveBlockmapPool(transports map[string]neural.TransportRate, ooni neural.OONIContext) (pool, avoid []string) {
	const minSamples = 10
	const goodRate = 0.3
	avoided := map[string]bool{}
	for name, r := range transports {
		if tot := r.OK + r.Fail; tot >= minSamples && r.Rate < goodRate {
			avoid = append(avoid, name)
			avoided[name] = true
		}
	}
	if ooni.TorBlocked {
		for _, t := range []string{"obfs4", "snowflake", "meek", "torsocks"} {
			if !avoided[t] {
				avoid = append(avoid, t)
				avoided[t] = true
			}
		}
	}
	for name := range transports {
		if !avoided[name] {
			pool = append(pool, name)
		}
	}
	return pool, avoid
}
