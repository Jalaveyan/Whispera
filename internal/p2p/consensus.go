package p2p

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
	"time"
)

const proposalStatusPending = "pending"

type ConsensusEngine struct {
	mu           sync.RWMutex
	proposals    map[string]*Proposal
	votes        map[string]map[string]*Vote
	leaders      map[string]string
	participants map[string]*Participant
	algorithms   map[string]ConsensusAlgorithm
	quorum       float64
	timeout      time.Duration
}

type Proposal struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Proposer    string                 `json:"proposer"`
	Created     time.Time              `json:"created"`
	Expires     time.Time              `json:"expires"`
	Status      string                 `json:"status"`
	Votes       int                    `json:"votes"`
	Threshold   int                    `json:"threshold"`
	Description string                 `json:"description"`
}

type Vote struct {
	ProposalID string    `json:"proposal_id"`
	Voter      string    `json:"voter"`
	Choice     string    `json:"choice"`
	Weight     float64   `json:"weight"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  []byte    `json:"signature"`
}

type Participant struct {
	ID         string    `json:"id"`
	Weight     float64   `json:"weight"`
	LastSeen   time.Time `json:"last_seen"`
	Reputation float64   `json:"reputation"`
	Stake      int64     `json:"stake"`
	Active     bool      `json:"active"`
}

type ConsensusAlgorithm interface {
	Vote(proposal *Proposal, voter string, choice string) error
	CountVotes(proposalID string) (map[string]int, error)
	IsQuorumReached(proposalID string) bool
	SelectLeader(service string) string
	ValidateProposal(proposal *Proposal) bool
}

type RaftAlgorithm struct {
	mu     sync.RWMutex
	state  string
	term   int
	leader string
	peers  map[string]*Participant
}

func (r *RaftAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return nil
}

func (r *RaftAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]int{"yes": 1, "no": 0}, nil
}

func (r *RaftAlgorithm) IsQuorumReached(proposalID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.peers) >= 3
}

func (r *RaftAlgorithm) SelectLeader(service string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.leader
}

func (r *RaftAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

type PBFTAlgorithm struct {
	mu      sync.RWMutex
	view    int
	primary string
	peers   map[string]*Participant
}

func (p *PBFTAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return nil
}

func (p *PBFTAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]int{"yes": 2, "no": 1}, nil
}

func (p *PBFTAlgorithm) IsQuorumReached(proposalID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers) >= 4
}

func (p *PBFTAlgorithm) SelectLeader(service string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.primary
}

func (p *PBFTAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

type PoSAlgorithm struct {
	mu     sync.RWMutex
	stakes map[string]int64
	peers  map[string]*Participant
}

func (p *PoSAlgorithm) Vote(proposal *Proposal, voter, choice string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return nil
}

func (p *PoSAlgorithm) CountVotes(proposalID string) (map[string]int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]int{"yes": 3, "no": 1}, nil
}

func (p *PoSAlgorithm) IsQuorumReached(proposalID string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers) >= 2
}

func (p *PoSAlgorithm) SelectLeader(service string) string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	maxStake := int64(0)
	leader := ""
	for nodeID, stake := range p.stakes {
		if stake > maxStake {
			maxStake = stake
			leader = nodeID
		}
	}
	return leader
}

func (p *PoSAlgorithm) ValidateProposal(proposal *Proposal) bool {
	return proposal != nil && proposal.Type != ""
}

func NewConsensusEngine() *ConsensusEngine {
	engine := &ConsensusEngine{
		proposals:    make(map[string]*Proposal),
		votes:        make(map[string]map[string]*Vote),
		leaders:      make(map[string]string),
		participants: make(map[string]*Participant),
		algorithms:   make(map[string]ConsensusAlgorithm),
		quorum:       0.67,
		timeout:      30 * time.Second,
	}

	engine.algorithms["raft"] = &RaftAlgorithm{
		state: "follower",
		term:  0,
		peers: make(map[string]*Participant),
	}
	engine.algorithms["pbft"] = &PBFTAlgorithm{
		view:    0,
		primary: "",
		peers:   make(map[string]*Participant),
	}
	engine.algorithms["pos"] = &PoSAlgorithm{
		stakes: make(map[string]int64),
		peers:  make(map[string]*Participant),
	}

	return engine
}

func (ce *ConsensusEngine) Start(ctx context.Context) {
	go ce.proposalProcessingLoop(ctx)

	go ce.leaderElectionLoop(ctx)

	go ce.participantMonitoringLoop(ctx)

	go ce.cleanupLoop(ctx)
}

func (ce *ConsensusEngine) proposalProcessingLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.processProposals()
		}
	}
}

func (ce *ConsensusEngine) leaderElectionLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.electLeaders()
		}
	}
}

func (ce *ConsensusEngine) participantMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.monitorParticipants()
		}
	}
}

func (ce *ConsensusEngine) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ce.cleanup()
		}
	}
}

func (ce *ConsensusEngine) CreateProposal(
	proposalType string, data map[string]interface{}, proposer string,
) (*Proposal, error) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	proposalID := ce.generateProposalID(proposer, proposalType)

	proposal := &Proposal{
		ID:          proposalID,
		Type:        proposalType,
		Data:        data,
		Proposer:    proposer,
		Created:     time.Now(),
		Expires:     time.Now().Add(ce.timeout),
		Status:      proposalStatusPending,
		Votes:       0,
		Threshold:   ce.calculateThreshold(),
		Description: fmt.Sprintf("Предложение %s от %s", proposalType, proposer),
	}

	ce.proposals[proposalID] = proposal
	ce.votes[proposalID] = make(map[string]*Vote)

	return proposal, nil
}

func (ce *ConsensusEngine) Vote(proposalID, voter, choice string) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	proposal, exists := ce.proposals[proposalID]
	if !exists {
		return fmt.Errorf("предложение %s не найдено", proposalID)
	}

	if proposal.Status != proposalStatusPending {
		return fmt.Errorf("предложение %s уже обработано", proposalID)
	}

	if time.Now().After(proposal.Expires) {
		proposal.Status = "expired"
		return fmt.Errorf("предложение %s истекло", proposalID)
	}

	if _, voted := ce.votes[proposalID][voter]; voted {
		return fmt.Errorf("участник %s уже голосовал", voter)
	}

	vote := &Vote{
		ProposalID: proposalID,
		Voter:      voter,
		Choice:     choice,
		Weight:     ce.getParticipantWeight(voter),
		Timestamp:  time.Now(),
		Signature:  ce.generateVoteSignature(voter, proposalID, choice),
	}

	ce.votes[proposalID][voter] = vote
	proposal.Votes++

	return nil
}

func (ce *ConsensusEngine) processProposals() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	for proposalID, proposal := range ce.proposals {
		if proposal.Status != proposalStatusPending {
			continue
		}

		if time.Now().After(proposal.Expires) {
			proposal.Status = "expired"
			continue
		}

		if ce.isQuorumReached(proposalID) {
			proposal.Status = "accepted"
		}
	}
}

func (ce *ConsensusEngine) electLeaders() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	services := []string{"routing", "encryption", "discovery", "monitoring"}

	for _, service := range services {
		leader := ce.selectLeaderForService(service)
		if leader != "" {
			ce.leaders[service] = leader
		}
	}
}

func (ce *ConsensusEngine) monitorParticipants() {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	active := 0
	totalWeight := 0.0

	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			active++
			totalWeight += participant.Weight
		}
	}

	fmt.Printf("   - Активных участников: %d/%d\n", active, len(ce.participants))
	fmt.Printf("   - Общий вес: %.2f\n", totalWeight)
	fmt.Printf("   - Лидеров: %d\n", len(ce.leaders))
}

func (ce *ConsensusEngine) cleanup() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	fmt.Println("🧹 Очистка устаревших данных консенсуса...")

	now := time.Now()
	cleaned := 0

	for proposalID, proposal := range ce.proposals {
		if now.Sub(proposal.Created) > 1*time.Hour {
			delete(ce.proposals, proposalID)
			delete(ce.votes, proposalID)
			cleaned++
		}
	}

	for participantID, participant := range ce.participants {
		if now.Sub(participant.LastSeen) > 30*time.Minute {
			delete(ce.participants, participantID)
			cleaned++
		}
	}

	if cleaned > 0 {
		fmt.Printf("✅ Очищено %d устаревших записей\n", cleaned)
	}
}

func (ce *ConsensusEngine) generateProposalID(proposer, proposalType string) string {
	data := fmt.Sprintf("%s:%s:%d", proposer, proposalType, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("prop_%x", hash[:8])
}

func (ce *ConsensusEngine) calculateThreshold() int {
	activeParticipants := 0
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			activeParticipants++
		}
	}

	threshold := int(float64(activeParticipants) * ce.quorum)
	if threshold < 1 {
		threshold = 1
	}

	return threshold
}

func (ce *ConsensusEngine) getParticipantWeight(participantID string) float64 {
	participant, exists := ce.participants[participantID]
	if !exists {
		return 1.0
	}

	return participant.Weight
}

func (ce *ConsensusEngine) generateVoteSignature(voter, proposalID, choice string) []byte {
	data := fmt.Sprintf("%s:%s:%s:%d", voter, proposalID, choice, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (ce *ConsensusEngine) isQuorumReached(proposalID string) bool {
	proposal := ce.proposals[proposalID]
	if proposal == nil {
		return false
	}

	return proposal.Votes >= proposal.Threshold
}

func (ce *ConsensusEngine) selectLeaderForService(_ string) string {
	participants := make([]*Participant, 0, len(ce.participants))
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			participants = append(participants, participant)
		}
	}

	if len(participants) == 0 {
		return ""
	}

	sort.Slice(participants, func(i, j int) bool {
		return participants[i].Weight > participants[j].Weight
	})

	leader := participants[0]
	return leader.ID
}

func (ce *ConsensusEngine) AddParticipant(participant *Participant) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	ce.participants[participant.ID] = participant
	fmt.Printf("👥 Добавлен участник консенсуса: %s (вес: %.2f)\n",
		participant.ID, participant.Weight)
}

func (ce *ConsensusEngine) RemoveParticipant(participantID string) {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	delete(ce.participants, participantID)
	fmt.Printf("👥 Удалён участник консенсуса: %s\n", participantID)
}

func (ce *ConsensusEngine) GetConsensusStats() map[string]interface{} {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	activeParticipants := 0
	for _, participant := range ce.participants {
		if time.Since(participant.LastSeen) < 5*time.Minute {
			activeParticipants++
		}
	}

	pendingProposals := 0
	for _, proposal := range ce.proposals {
		if proposal.Status == proposalStatusPending {
			pendingProposals++
		}
	}

	return map[string]interface{}{
		"total_participants":  len(ce.participants),
		"active_participants": activeParticipants,
		"total_proposals":     len(ce.proposals),
		"pending_proposals":   pendingProposals,
		"leaders":             len(ce.leaders),
		"quorum_threshold":    ce.quorum,
		"algorithms":          len(ce.algorithms),
	}
}

func (ce *ConsensusEngine) GetLeader(service string) string {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if leader, exists := ce.leaders[service]; exists && leader != "" {
		return leader
	}

	var bestParticipant *Participant
	bestScore := 0.0

	for _, participant := range ce.participants {
		if !participant.Active {
			continue
		}

		score := participant.Weight * participant.Reputation
		if score > bestScore {
			bestScore = score
			bestParticipant = participant
		}
	}

	if bestParticipant != nil {
		ce.leaders[service] = bestParticipant.ID
		return bestParticipant.ID
	}

	return ""
}

func (ce *ConsensusEngine) GetProposal(proposalID string) (*Proposal, error) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	proposal, exists := ce.proposals[proposalID]
	if !exists {
		return nil, fmt.Errorf("предложение %s не найдено", proposalID)
	}

	return proposal, nil
}

func (ce *ConsensusEngine) GetVotes(proposalID string) ([]*Vote, error) {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	votes, exists := ce.votes[proposalID]
	if !exists {
		return nil, fmt.Errorf("голоса для предложения %s не найдены", proposalID)
	}

	voteList := make([]*Vote, 0, len(votes))
	for _, vote := range votes {
		voteList = append(voteList, vote)
	}

	return voteList, nil
}
