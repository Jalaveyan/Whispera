package tunnel

import (
	"context"
)

func (m *Manager) pickServer(ctx context.Context) string { return m.ml.pickServer(ctx) }
