package p2p

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

func secureRandInt(maxVal int) int {
	if maxVal <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxVal)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}

func secureRandFloat64() float64 {
	b := make([]byte, 8)
	if _, err := crand.Read(b); err != nil {
		return 0.0
	}
	val := binary.BigEndian.Uint64(b)
	return float64(val) / float64(^uint64(0))
}

type RoutingTable struct {
	mu      sync.RWMutex
	buckets [160][]*Node
	myID    string
}

type Route struct {
	Destination string        `json:"destination"`
	Path        []string      `json:"path"`
	Latency     time.Duration `json:"latency"`
	Reliability float64       `json:"reliability"`
	LastUsed    time.Time     `json:"last_used"`
}

type RoutingEngine struct {
	mu         sync.RWMutex
	routes     map[string]*Route
	table      *RoutingTable
	metrics    map[string]*NodeMetrics
	algorithms map[string]RoutingAlgorithm
	bestRoutes map[string]*Route
}

type NodeMetrics struct {
	Latency            time.Duration `json:"latency"`
	Reliability        float64       `json:"reliability"`
	Throughput         int64         `json:"throughput"`
	LastSeen           time.Time     `json:"last_seen"`
	Connections        int           `json:"connections"`
	Uptime             time.Duration `json:"uptime"`
	LastRTT            int64         `json:"last_rtt"`
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
}

type RoutingAlgorithm interface {
	FindRoute(destination string, availableNodes []*Node) *Route
	UpdateMetrics(nodeID string, metrics *NodeMetrics)
	GetBestNodes(count int) []*Node
}

type DHTAlgorithm struct {
	mu    sync.RWMutex
	table *RoutingTable
}

type FloodingAlgorithm struct {
	mu    sync.RWMutex
	nodes map[string]*Node
}

type AStarAlgorithm struct {
	mu    sync.RWMutex
	graph map[string][]string
	costs map[string]float64
}

func NewRoutingEngine(myNodeID string) *RoutingEngine {
	engine := &RoutingEngine{
		routes:     make(map[string]*Route),
		table:      NewRoutingTable(myNodeID),
		metrics:    make(map[string]*NodeMetrics),
		algorithms: make(map[string]RoutingAlgorithm),
		bestRoutes: make(map[string]*Route),
	}

	engine.algorithms["dht"] = &DHTAlgorithm{table: engine.table}
	engine.algorithms["flooding"] = &FloodingAlgorithm{nodes: make(map[string]*Node)}
	engine.algorithms["astar"] = &AStarAlgorithm{
		graph: make(map[string][]string),
		costs: make(map[string]float64),
	}

	return engine
}

func NewRoutingTable(myNodeID string) *RoutingTable {
	return &RoutingTable{
		myID: myNodeID,
	}
}

func (re *RoutingEngine) Start(ctx context.Context) {
	go re.updateMetricsLoop(ctx)

	go re.optimizeRoutesLoop(ctx)

	go re.performanceAnalysisLoop(ctx)
}

func (re *RoutingEngine) updateMetricsLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			re.updateAllMetrics()
		}
	}
}

func (re *RoutingEngine) optimizeRoutesLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			re.optimizeAllRoutes()
		}
	}
}

func (re *RoutingEngine) performanceAnalysisLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			re.analyzePerformance()
		}
	}
}

func (re *RoutingEngine) FindBestRoute(destination string) (*Route, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	if route, exists := re.bestRoutes[destination]; exists {
		if time.Since(route.LastUsed) < 5*time.Minute {
			return route, nil
		}
	}

	availableNodes := re.getAvailableNodes()

	algorithms := []string{"dht", "astar", "flooding"}
	for _, algoName := range algorithms {
		algorithm := re.algorithms[algoName]
		route := algorithm.FindRoute(destination, availableNodes)
		if route != nil {
			re.bestRoutes[destination] = route
			return route, nil
		}
	}

	return nil, fmt.Errorf("маршрут к %s не найден", destination)
}

func (re *RoutingEngine) getAvailableNodes() []*Node {
	re.mu.RLock()
	defer re.mu.RUnlock()

	nodes := make([]*Node, 0)
	for nodeID, metrics := range re.metrics {
		if time.Since(metrics.LastSeen) < 5*time.Minute {
			node := &Node{
				ID:          nodeID,
				Latency:     metrics.Latency,
				Reliability: metrics.Reliability,
				LastSeen:    metrics.LastSeen,
			}
			nodes = append(nodes, node)
		}
	}

	return nodes
}

func (re *RoutingEngine) updateAllMetrics() {
	re.mu.Lock()
	defer re.mu.Unlock()

	for _, metrics := range re.metrics {
		if metrics.LastRTT > 0 {
			metrics.Latency = time.Duration(metrics.LastRTT) * time.Millisecond
		} else {
			metrics.Latency = 50 * time.Millisecond
		}

		if metrics.TotalRequests > 0 {
			metrics.Reliability = float64(metrics.SuccessfulRequests) / float64(metrics.TotalRequests)
		} else {
			metrics.Reliability = 0.8
		}

		metrics.LastSeen = time.Now()
	}
}

func (re *RoutingEngine) optimizeAllRoutes() {
	re.mu.Lock()
	defer re.mu.Unlock()

	for dest, route := range re.bestRoutes {
		if time.Since(route.LastUsed) > 10*time.Minute {
			delete(re.bestRoutes, dest)
		}
	}
}

func (re *RoutingEngine) analyzePerformance() {
	re.mu.RLock()
	defer re.mu.RUnlock()

	totalRoutes := len(re.bestRoutes)
	activeNodes := len(re.metrics)

	_ = totalRoutes
	_ = activeNodes

	goodRoutes := 0
	for _, route := range re.bestRoutes {
		if route.Reliability > 0.8 {
			goodRoutes++
		}
	}

	quality := float64(goodRoutes) / float64(totalRoutes) * 100
	_ = quality
}

func (re *RoutingEngine) AddNode(node *Node) {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.metrics[node.ID] = &NodeMetrics{
		Latency:     node.Latency,
		Reliability: node.Reliability,
		LastSeen:    node.LastSeen,
		Uptime:      time.Since(node.LastSeen),
	}

	re.table.AddNode(node)
}

func (re *RoutingEngine) RemoveNode(nodeID string) {
	re.mu.Lock()
	defer re.mu.Unlock()

	delete(re.metrics, nodeID)
	re.table.RemoveNode(nodeID)

	for dest, route := range re.bestRoutes {
		for _, pathNodeID := range route.Path {
			if pathNodeID == nodeID {
				delete(re.bestRoutes, dest)
				break
			}
		}
	}
}

func (re *RoutingEngine) GetRoutingStats() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	return map[string]interface{}{
		"total_routes": len(re.bestRoutes),
		"active_nodes": len(re.metrics),
		"dht_buckets":  re.table.GetBucketCount(),
		"algorithms":   len(re.algorithms),
	}
}

func (rt *RoutingTable) AddNode(node *Node) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	distance := rt.calculateDistance(rt.myID, node.ID)
	bucketIndex := rt.getBucketIndex(distance)

	rt.buckets[bucketIndex] = append(rt.buckets[bucketIndex], node)

	if len(rt.buckets[bucketIndex]) > 20 {
		rt.buckets[bucketIndex] = rt.buckets[bucketIndex][1:]
	}
}

func (rt *RoutingTable) RemoveNode(nodeID string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for i := range rt.buckets {
		bucket := &rt.buckets[i]
		for j, node := range *bucket {
			if node.ID == nodeID {
				rt.buckets[i] = append((*bucket)[:j], (*bucket)[j+1:]...)
				return
			}
		}
	}
}

func (rt *RoutingTable) calculateDistance(id1, id2 string) string {
	hash1 := sha256.Sum256([]byte(id1))
	hash2 := sha256.Sum256([]byte(id2))

	result := make([]byte, 32)
	for i := 0; i < 32; i++ {
		result[i] = hash1[i] ^ hash2[i]
	}

	return fmt.Sprintf("%x", result)
}

func (rt *RoutingTable) getBucketIndex(distance string) int {
	var bytesBuf [32]byte
	n := 0
	for i := 0; i+1 < len(distance) && n < 32; i += 2 {
		var b byte
		var ok bool
		if v, e := fmt.Sscanf(distance[i:i+2], "%02x", &b); v == 1 && e == nil {
			bytesBuf[n] = b
			n++
			ok = true
		}
		if !ok {
			return 0
		}
	}
	bitIndex := -1
	for i := 0; i < 20 && i < n; i++ {
		b := bytesBuf[i]
		if b == 0 {
			continue
		}
		msb := 7
		for msb >= 0 {
			if (b & (1 << uint(msb))) != 0 {
				break
			}
			msb--
		}
		bitIndex = i*8 + (7 - msb)
		break
	}
	if bitIndex < 0 {
		return 159
	}
	if bitIndex >= 160 {
		return 159
	}
	return 159 - bitIndex
}

func (rt *RoutingTable) GetBucketCount() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	count := 0
	for i := range rt.buckets {
		bucket := &rt.buckets[i]
		if len(*bucket) > 0 {
			count++
		}
	}
	return count
}

func (dht *DHTAlgorithm) FindRoute(destination string, availableNodes []*Node) *Route {
	dht.mu.RLock()
	defer dht.mu.RUnlock()

	closestNodes := dht.findClosestNodes(destination, 3)
	if len(closestNodes) == 0 {
		return nil
	}

	path := make([]string, len(closestNodes))
	for i, node := range closestNodes {
		path[i] = node.ID
	}

	return &Route{
		Destination: destination,
		Path:        path,
		Latency:     time.Duration(secureRandInt(100)) * time.Millisecond,
		Reliability: 0.8 + secureRandFloat64()*0.2,
		LastUsed:    time.Now(),
	}
}

func (dht *DHTAlgorithm) findClosestNodes(_ string, count int) []*Node {
	nodes := make([]*Node, 0)

	for i := range dht.table.buckets {
		bucket := &dht.table.buckets[i]
		for _, node := range *bucket {
			if len(nodes) < count {
				nodes = append(nodes, node)
			}
		}
	}

	return nodes
}

func (dht *DHTAlgorithm) UpdateMetrics(nodeID string, metrics *NodeMetrics) {
}

func (dht *DHTAlgorithm) GetBestNodes(count int) []*Node {
	dht.mu.RLock()
	defer dht.mu.RUnlock()

	allNodes := make([]*Node, 0)
	for i := range dht.table.buckets {
		bucket := &dht.table.buckets[i]
		allNodes = append(allNodes, *bucket...)
	}

	sort.Slice(allNodes, func(i, j int) bool {
		return allNodes[i].Reliability > allNodes[j].Reliability
	})

	if len(allNodes) > count {
		return allNodes[:count]
	}
	return allNodes
}

func (flood *FloodingAlgorithm) FindRoute(destination string, availableNodes []*Node) *Route {
	flood.mu.RLock()
	defer flood.mu.RUnlock()

	if len(availableNodes) == 0 {
		return nil
	}

	path := make([]string, len(availableNodes))
	for i, node := range availableNodes {
		path[i] = node.ID
	}

	return &Route{
		Destination: destination,
		Path:        path,
		Latency:     time.Duration(secureRandInt(200)) * time.Millisecond,
		Reliability: 0.7 + secureRandFloat64()*0.3,
		LastUsed:    time.Now(),
	}
}

func (flood *FloodingAlgorithm) UpdateMetrics(nodeID string, metrics *NodeMetrics) {
}

func (flood *FloodingAlgorithm) GetBestNodes(count int) []*Node {
	flood.mu.RLock()
	defer flood.mu.RUnlock()

	allNodes := make([]*Node, 0, len(flood.nodes))
	for _, node := range flood.nodes {
		allNodes = append(allNodes, node)
	}

	if len(allNodes) > count {
		return allNodes[:count]
	}
	return allNodes
}

func (astar *AStarAlgorithm) FindRoute(destination string, availableNodes []*Node) *Route {
	astar.mu.RLock()
	defer astar.mu.RUnlock()

	if len(availableNodes) == 0 {
		return nil
	}

	path := make([]string, 0)
	visited := make(map[string]bool)

	current := availableNodes[0]
	path = append(path, current.ID)
	visited[current.ID] = true

	for _, node := range availableNodes[1:] {
		if !visited[node.ID] && len(path) < 5 {
			path = append(path, node.ID)
			visited[node.ID] = true
		}
	}

	return &Route{
		Destination: destination,
		Path:        path,
		Latency:     time.Duration(secureRandInt(150)) * time.Millisecond,
		Reliability: 0.85 + secureRandFloat64()*0.15,
		LastUsed:    time.Now(),
	}
}

func (astar *AStarAlgorithm) UpdateMetrics(nodeID string, metrics *NodeMetrics) {
	astar.mu.Lock()
	defer astar.mu.Unlock()

	astar.costs[nodeID] = float64(metrics.Latency) / float64(time.Millisecond)
}

func (astar *AStarAlgorithm) GetBestNodes(count int) []*Node {
	astar.mu.RLock()
	defer astar.mu.RUnlock()

	type nodeCost struct {
		nodeID string
		cost   float64
	}

	costs := make([]nodeCost, 0, len(astar.costs))
	for nodeID, cost := range astar.costs {
		costs = append(costs, nodeCost{nodeID, cost})
	}

	sort.Slice(costs, func(i, j int) bool {
		return costs[i].cost < costs[j].cost
	})

	bestNodes := make([]*Node, 0, count)
	for _, nc := range costs {
		if len(bestNodes) >= count {
			break
		}
		node := &Node{
			ID: nc.nodeID,
		}
		bestNodes = append(bestNodes, node)
	}

	return bestNodes
}
