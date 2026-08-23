package keylimits

import (
	"fmt"
	"testing"
	"time"
)

func newTestManager(ipCap int) *Manager {
	return New(Limits{
		MaxActiveSessions: 100,
		SoftIPCap:         ipCap,
		SessionTTL:        time.Hour,
	})
}

func TestOverCapKeepsEstablishedSessions(t *testing.T) {
	m := newTestManager(5)

	for i := 0; i < 5; i++ {
		sid := fmt.Sprintf("session-%d", i)
		ip := fmt.Sprintf("10.0.0.%d", i)
		if reason, msg := m.Admit("key", sid, ip); reason != ReasonNone {
			t.Fatalf("admitting IP %d of 5 failed: %s (%s)", i+1, reason, msg)
		}
	}

	reason, msg := m.Admit("key", "session-6", "10.0.0.99")
	if reason != ReasonSoftIPCap {
		t.Fatalf("6th IP got %q, want %q", reason, ReasonSoftIPCap)
	}
	if msg == "" {
		t.Error("a refusal must carry a message for the client")
	}

	snap := m.Snapshot("key")
	if snap.ActiveSessions != 5 {
		t.Fatalf("after the refusal %d sessions remain, want the original 5", snap.ActiveSessions)
	}
	for i := 0; i < 5; i++ {
		sid := fmt.Sprintf("session-%d", i)
		found := false
		for _, s := range snap.Sessions {
			if s.SessionID == sid {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was dropped by a refusal aimed at someone else", sid)
		}
	}
}

func TestReleaseFreesTheSlot(t *testing.T) {
	m := newTestManager(5)

	for i := 0; i < 5; i++ {
		if reason, _ := m.Admit("key", fmt.Sprintf("session-%d", i), fmt.Sprintf("10.0.0.%d", i)); reason != ReasonNone {
			t.Fatalf("setup admit %d failed: %s", i, reason)
		}
	}
	if reason, _ := m.Admit("key", "late", "10.0.0.99"); reason != ReasonSoftIPCap {
		t.Fatalf("expected the cap to hold, got %s", reason)
	}

	m.Release("key", "session-0")

	if reason, msg := m.Admit("key", "late", "10.0.0.99"); reason != ReasonNone {
		t.Fatalf("a freed slot was not reusable: %s (%s)", reason, msg)
	}
}

func TestSameSessionAcrossFlowsTakesOneSlot(t *testing.T) {
	m := newTestManager(5)

	for i := 0; i < 20; i++ {
		if reason, msg := m.Admit("key", "one-session", "10.0.0.1"); reason != ReasonNone {
			t.Fatalf("flow %d of the same session was refused: %s (%s)", i, reason, msg)
		}
	}

	if got := m.Snapshot("key").ActiveSessions; got != 1 {
		t.Fatalf("20 flows of one session produced %d slots, want 1", got)
	}
}
