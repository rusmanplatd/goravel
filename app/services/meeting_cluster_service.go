package services

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
	"github.com/redis/go-redis/v9"
)

// MeetingClusterService handles distributed meeting management
type MeetingClusterService struct {
	redisClient    *redis.Client
	nodeID         string
	nodeInfo       *ClusterNode
	loadBalancer   *LoadBalancer
	stateManager   *DistributedStateManager
	lockManager    *DistributedLockManager
	healthChecker  *ClusterHealthChecker
	mu             sync.RWMutex
	activeMeetings map[string]*DistributedMeeting
	shutdownChan   chan struct{}
}

// ClusterNode represents a node in the meeting cluster
type ClusterNode struct {
	ID               string                 `json:"id"`
	Address          string                 `json:"address"`
	Port             int                    `json:"port"`
	Region           string                 `json:"region"`
	Zone             string                 `json:"zone"`
	Capacity         int                    `json:"capacity"`
	CurrentLoad      int                    `json:"current_load"`
	CPUUsage         float64                `json:"cpu_usage"`
	MemoryUsage      float64                `json:"memory_usage"`
	NetworkBandwidth float64                `json:"network_bandwidth"`
	Status           string                 `json:"status"` // healthy, degraded, unhealthy
	LastHeartbeat    time.Time              `json:"last_heartbeat"`
	Metadata         map[string]interface{} `json:"metadata"`
	Capabilities     []string               `json:"capabilities"`
}

// DistributedMeeting represents a meeting in the distributed system
type DistributedMeeting struct {
	MeetingID        string                 `json:"meeting_id"`
	PrimaryNode      string                 `json:"primary_node"`
	ReplicaNodes     []string               `json:"replica_nodes"`
	State            string                 `json:"state"`
	ParticipantCount int                    `json:"participant_count"`
	StartTime        time.Time              `json:"start_time"`
	LastUpdate       time.Time              `json:"last_update"`
	Metadata         map[string]interface{} `json:"metadata"`
	LoadBalanceKey   string                 `json:"load_balance_key"`
}

// LoadBalancer handles meeting distribution across nodes
type LoadBalancer struct {
	strategy string // round_robin, least_connections, consistent_hash, geographic
	nodes    map[string]*ClusterNode
	hashRing *ConsistentHashRing
	mu       sync.RWMutex
}

// ConsistentHashRing implements consistent hashing for load balancing
type ConsistentHashRing struct {
	nodes      map[uint32]string
	sortedKeys []uint32
	mu         sync.RWMutex
}

// DistributedStateManager manages meeting state across the cluster
type DistributedStateManager struct {
	redisClient      *redis.Client
	keyPrefix        string
	syncInterval     time.Duration
	conflictResolver *ConflictResolver
}

// DistributedLockManager manages distributed locks for meeting operations
type DistributedLockManager struct {
	redisClient *redis.Client
	lockTTL     time.Duration
	retryDelay  time.Duration
	maxRetries  int
}

// ClusterHealthChecker monitors cluster health
type ClusterHealthChecker struct {
	redisClient        *redis.Client
	checkInterval      time.Duration
	unhealthyThreshold time.Duration
	nodes              map[string]*ClusterNode
	mu                 sync.RWMutex
}

// ConflictResolver handles state conflicts in distributed scenarios
type ConflictResolver struct {
	strategy string // last_write_wins, merge, custom
}

// DistributedLock represents a distributed lock
type DistributedLock struct {
	Key        string
	Value      string
	TTL        time.Duration
	AcquiredAt time.Time
}

// MeetingPartition represents a meeting partition for scaling
type MeetingPartition struct {
	ID           string    `json:"id"`
	MeetingID    string    `json:"meeting_id"`
	NodeID       string    `json:"node_id"`
	Participants []string  `json:"participants"`
	State        string    `json:"state"`
	CreatedAt    time.Time `json:"created_at"`
}

// NodeMetrics contains node performance metrics
type NodeMetrics struct {
	NodeID            string    `json:"node_id"`
	CPUUsage          float64   `json:"cpu_usage"`
	MemoryUsage       float64   `json:"memory_usage"`
	NetworkIn         float64   `json:"network_in_mbps"`
	NetworkOut        float64   `json:"network_out_mbps"`
	ActiveMeetings    int       `json:"active_meetings"`
	TotalParticipants int       `json:"total_participants"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	ResponseTimeMs    float64   `json:"response_time_ms"`
	ErrorRate         float64   `json:"error_rate"`
	LastUpdated       time.Time `json:"last_updated"`
}

// NewMeetingClusterService creates a new cluster service
func NewMeetingClusterService(nodeID string) *MeetingClusterService {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     facades.Config().GetString("redis.host") + ":" + facades.Config().GetString("redis.port"),
		Password: facades.Config().GetString("redis.password"),
		DB:       facades.Config().GetInt("redis.database", 0),
	})

	nodeInfo := &ClusterNode{
		ID:           nodeID,
		Address:      facades.Config().GetString("app.host", "localhost"),
		Port:         facades.Config().GetInt("app.port", 8080),
		Region:       facades.Config().GetString("cluster.region", "default"),
		Zone:         facades.Config().GetString("cluster.zone", "default"),
		Capacity:     facades.Config().GetInt("cluster.capacity", 1000),
		Status:       "healthy",
		Capabilities: []string{"video", "audio", "screen_share", "recording"},
		Metadata:     make(map[string]interface{}),
	}

	service := &MeetingClusterService{
		redisClient:    redisClient,
		nodeID:         nodeID,
		nodeInfo:       nodeInfo,
		activeMeetings: make(map[string]*DistributedMeeting),
		shutdownChan:   make(chan struct{}),
	}

	// Initialize components
	service.loadBalancer = NewLoadBalancer(redisClient)
	service.stateManager = NewDistributedStateManager(redisClient)
	service.lockManager = NewDistributedLockManager(redisClient)
	service.healthChecker = NewClusterHealthChecker(redisClient)

	// Start background services
	go service.heartbeatLoop()
	go service.stateSync()
	go service.healthMonitoring()
	go service.loadBalancing()

	// Register node
	service.registerNode()

	return service
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(redisClient *redis.Client) *LoadBalancer {
	return &LoadBalancer{
		strategy: facades.Config().GetString("cluster.load_balance.strategy", "consistent_hash"),
		nodes:    make(map[string]*ClusterNode),
		hashRing: NewConsistentHashRing(),
	}
}

// NewConsistentHashRing creates a new consistent hash ring
func NewConsistentHashRing() *ConsistentHashRing {
	return &ConsistentHashRing{
		nodes:      make(map[uint32]string),
		sortedKeys: make([]uint32, 0),
	}
}

// NewDistributedStateManager creates a new state manager
func NewDistributedStateManager(redisClient *redis.Client) *DistributedStateManager {
	return &DistributedStateManager{
		redisClient:      redisClient,
		keyPrefix:        "meeting:state:",
		syncInterval:     facades.Config().GetDuration("cluster.state_sync_interval", 5*time.Second),
		conflictResolver: &ConflictResolver{strategy: "last_write_wins"},
	}
}

// NewDistributedLockManager creates a new lock manager
func NewDistributedLockManager(redisClient *redis.Client) *DistributedLockManager {
	return &DistributedLockManager{
		redisClient: redisClient,
		lockTTL:     facades.Config().GetDuration("cluster.lock_ttl", 30*time.Second),
		retryDelay:  facades.Config().GetDuration("cluster.lock_retry_delay", 100*time.Millisecond),
		maxRetries:  facades.Config().GetInt("cluster.lock_max_retries", 50),
	}
}

// NewClusterHealthChecker creates a new health checker
func NewClusterHealthChecker(redisClient *redis.Client) *ClusterHealthChecker {
	return &ClusterHealthChecker{
		redisClient:        redisClient,
		checkInterval:      facades.Config().GetDuration("cluster.health_check_interval", 10*time.Second),
		unhealthyThreshold: facades.Config().GetDuration("cluster.unhealthy_threshold", 60*time.Second),
		nodes:              make(map[string]*ClusterNode),
	}
}

// StartMeeting starts a meeting in the distributed system
func (mcs *MeetingClusterService) StartMeeting(meetingID, hostUserID string) (*DistributedMeeting, error) {
	// Acquire distributed lock
	lockKey := fmt.Sprintf("meeting:lock:%s", meetingID)
	lock, err := mcs.lockManager.AcquireLock(context.Background(), lockKey)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire meeting lock: %v", err)
	}
	defer mcs.lockManager.ReleaseLock(context.Background(), lock)

	// Check if meeting already exists
	existingMeeting, err := mcs.stateManager.GetMeetingState(meetingID)
	if err == nil && existingMeeting != nil {
		return nil, fmt.Errorf("meeting already active: %s", meetingID)
	}

	// Select optimal node for the meeting
	selectedNode, err := mcs.loadBalancer.SelectNode(meetingID, map[string]interface{}{
		"host_user_id": hostUserID,
		"meeting_type": "video",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to select node: %v", err)
	}

	// Create distributed meeting
	distributedMeeting := &DistributedMeeting{
		MeetingID:        meetingID,
		PrimaryNode:      selectedNode.ID,
		ReplicaNodes:     mcs.selectReplicaNodes(selectedNode, 2),
		State:            "starting",
		ParticipantCount: 0,
		StartTime:        time.Now(),
		LastUpdate:       time.Now(),
		Metadata: map[string]interface{}{
			"host_user_id": hostUserID,
			"created_by":   mcs.nodeID,
		},
		LoadBalanceKey: mcs.generateLoadBalanceKey(meetingID),
	}

	// Store meeting state
	if err := mcs.stateManager.SetMeetingState(meetingID, distributedMeeting); err != nil {
		return nil, fmt.Errorf("failed to store meeting state: %v", err)
	}

	// Add to local cache if this node is primary or replica
	if selectedNode.ID == mcs.nodeID || mcs.isReplicaNode(distributedMeeting, mcs.nodeID) {
		mcs.mu.Lock()
		mcs.activeMeetings[meetingID] = distributedMeeting
		mcs.mu.Unlock()
	}

	// Update meeting state to active
	distributedMeeting.State = "active"
	mcs.stateManager.SetMeetingState(meetingID, distributedMeeting)

	// Notify cluster about new meeting
	mcs.broadcastMeetingEvent("meeting_started", meetingID, map[string]interface{}{
		"primary_node":     selectedNode.ID,
		"replica_nodes":    distributedMeeting.ReplicaNodes,
		"host_user_id":     hostUserID,
		"load_balance_key": distributedMeeting.LoadBalanceKey,
	})

	facades.Log().Info("Distributed meeting started", map[string]interface{}{
		"meeting_id":    meetingID,
		"primary_node":  selectedNode.ID,
		"replica_nodes": distributedMeeting.ReplicaNodes,
		"host_user_id":  hostUserID,
		"node_id":       mcs.nodeID,
	})

	return distributedMeeting, nil
}

// JoinMeeting allows a participant to join a distributed meeting
func (mcs *MeetingClusterService) JoinMeeting(meetingID, userID string, deviceInfo map[string]interface{}) error {
	// Get meeting state
	meeting, err := mcs.stateManager.GetMeetingState(meetingID)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	if meeting.State != "active" {
		return fmt.Errorf("meeting is not active")
	}

	// Acquire lock for participant operations
	lockKey := fmt.Sprintf("meeting:participant:lock:%s:%s", meetingID, userID)
	lock, err := mcs.lockManager.AcquireLock(context.Background(), lockKey)
	if err != nil {
		return fmt.Errorf("failed to acquire participant lock: %v", err)
	}
	defer mcs.lockManager.ReleaseLock(context.Background(), lock)

	// Check if participant already joined
	participantKey := fmt.Sprintf("meeting:participant:%s:%s", meetingID, userID)
	exists, err := mcs.redisClient.Exists(context.Background(), participantKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check participant existence: %v", err)
	}
	if exists > 0 {
		return fmt.Errorf("participant already joined")
	}

	// Determine which node should handle this participant
	targetNode, err := mcs.loadBalancer.SelectNodeForParticipant(meetingID, userID, deviceInfo)
	if err != nil {
		return fmt.Errorf("failed to select node for participant: %v", err)
	}

	// Create participant record
	participant := map[string]interface{}{
		"user_id":     userID,
		"meeting_id":  meetingID,
		"node_id":     targetNode.ID,
		"device_info": deviceInfo,
		"joined_at":   time.Now(),
		"status":      "joining",
	}

	// Store participant information
	participantJSON, _ := json.Marshal(participant)
	err = mcs.redisClient.Set(context.Background(), participantKey, participantJSON, time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to store participant: %v", err)
	}

	// Add participant to meeting participant set
	participantSetKey := fmt.Sprintf("meeting:participants:%s", meetingID)
	err = mcs.redisClient.SAdd(context.Background(), participantSetKey, userID).Err()
	if err != nil {
		return fmt.Errorf("failed to add participant to set: %v", err)
	}

	// Update meeting participant count
	meeting.ParticipantCount++
	meeting.LastUpdate = time.Now()
	mcs.stateManager.SetMeetingState(meetingID, meeting)

	// Notify cluster about participant join
	mcs.broadcastMeetingEvent("participant_joined", meetingID, map[string]interface{}{
		"user_id":           userID,
		"target_node":       targetNode.ID,
		"participant_count": meeting.ParticipantCount,
		"device_info":       deviceInfo,
	})

	facades.Log().Info("Participant joined distributed meeting", map[string]interface{}{
		"meeting_id":  meetingID,
		"user_id":     userID,
		"target_node": targetNode.ID,
		"node_id":     mcs.nodeID,
	})

	return nil
}

// EndMeeting ends a distributed meeting
func (mcs *MeetingClusterService) EndMeeting(meetingID, hostUserID string) error {
	// Acquire distributed lock
	lockKey := fmt.Sprintf("meeting:lock:%s", meetingID)
	lock, err := mcs.lockManager.AcquireLock(context.Background(), lockKey)
	if err != nil {
		return fmt.Errorf("failed to acquire meeting lock: %v", err)
	}
	defer mcs.lockManager.ReleaseLock(context.Background(), lock)

	// Get meeting state
	meeting, err := mcs.stateManager.GetMeetingState(meetingID)
	if err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Update meeting state
	meeting.State = "ending"
	meeting.LastUpdate = time.Now()
	mcs.stateManager.SetMeetingState(meetingID, meeting)

	// Clean up participants
	participantSetKey := fmt.Sprintf("meeting:participants:%s", meetingID)
	participants, err := mcs.redisClient.SMembers(context.Background(), participantSetKey).Result()
	if err == nil {
		for _, userID := range participants {
			participantKey := fmt.Sprintf("meeting:participant:%s:%s", meetingID, userID)
			mcs.redisClient.Del(context.Background(), participantKey)
		}
		mcs.redisClient.Del(context.Background(), participantSetKey)
	}

	// Remove from local cache
	mcs.mu.Lock()
	delete(mcs.activeMeetings, meetingID)
	mcs.mu.Unlock()

	// Remove from distributed state
	mcs.stateManager.DeleteMeetingState(meetingID)

	// Notify cluster about meeting end
	mcs.broadcastMeetingEvent("meeting_ended", meetingID, map[string]interface{}{
		"ended_by":          hostUserID,
		"participant_count": len(participants),
		"duration":          time.Since(meeting.StartTime),
	})

	facades.Log().Info("Distributed meeting ended", map[string]interface{}{
		"meeting_id":        meetingID,
		"ended_by":          hostUserID,
		"participant_count": len(participants),
		"duration":          time.Since(meeting.StartTime),
		"node_id":           mcs.nodeID,
	})

	return nil
}

// SelectNode selects the optimal node for a meeting
func (lb *LoadBalancer) SelectNode(meetingID string, metadata map[string]interface{}) (*ClusterNode, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.nodes) == 0 {
		return nil, fmt.Errorf("no available nodes")
	}

	switch lb.strategy {
	case "consistent_hash":
		return lb.selectByConsistentHash(meetingID)
	case "least_connections":
		return lb.selectByLeastConnections()
	case "geographic":
		return lb.selectByGeography(metadata)
	case "round_robin":
		return lb.selectByRoundRobin()
	default:
		return lb.selectByLeastConnections()
	}
}

// SelectNodeForParticipant selects optimal node for a participant
func (lb *LoadBalancer) SelectNodeForParticipant(meetingID, userID string, deviceInfo map[string]interface{}) (*ClusterNode, error) {
	// For participants, try to use the same node as the meeting if possible
	// Otherwise, select based on load and geographic proximity

	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// Try to find the meeting's primary node first
	for _, node := range lb.nodes {
		if node.Status == "healthy" && node.CurrentLoad < node.Capacity {
			return node, nil
		}
	}

	return nil, fmt.Errorf("no suitable node found for participant")
}

// selectByConsistentHash selects node using consistent hashing
func (lb *LoadBalancer) selectByConsistentHash(key string) (*ClusterNode, error) {
	nodeID := lb.hashRing.GetNode(key)
	if nodeID == "" {
		return nil, fmt.Errorf("no node found in hash ring")
	}

	node, exists := lb.nodes[nodeID]
	if !exists || node.Status != "healthy" {
		return lb.selectByLeastConnections() // Fallback
	}

	return node, nil
}

// selectByLeastConnections selects node with least connections
func (lb *LoadBalancer) selectByLeastConnections() (*ClusterNode, error) {
	var selectedNode *ClusterNode
	minLoad := int(^uint(0) >> 1) // Max int

	for _, node := range lb.nodes {
		if node.Status == "healthy" && node.CurrentLoad < minLoad && node.CurrentLoad < node.Capacity {
			selectedNode = node
			minLoad = node.CurrentLoad
		}
	}

	if selectedNode == nil {
		return nil, fmt.Errorf("no healthy nodes available")
	}

	return selectedNode, nil
}

// selectByGeography selects node based on geographic proximity
func (lb *LoadBalancer) selectByGeography(metadata map[string]interface{}) (*ClusterNode, error) {
	// Implementation would consider user location and node regions
	return lb.selectByLeastConnections() // Fallback for now
}

// selectByRoundRobin selects node using round-robin
func (lb *LoadBalancer) selectByRoundRobin() (*ClusterNode, error) {
	// Implementation would maintain round-robin state
	return lb.selectByLeastConnections() // Fallback for now
}

// GetNode returns a node from the consistent hash ring
func (chr *ConsistentHashRing) GetNode(key string) string {
	chr.mu.RLock()
	defer chr.mu.RUnlock()

	if len(chr.sortedKeys) == 0 {
		return ""
	}

	hash := chr.hash(key)

	// Find the first node with hash >= key hash
	idx := sort.Search(len(chr.sortedKeys), func(i int) bool {
		return chr.sortedKeys[i] >= hash
	})

	// Wrap around if necessary
	if idx == len(chr.sortedKeys) {
		idx = 0
	}

	return chr.nodes[chr.sortedKeys[idx]]
}

// AddNode adds a node to the consistent hash ring
func (chr *ConsistentHashRing) AddNode(nodeID string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()

	// Add multiple virtual nodes for better distribution
	for i := 0; i < 150; i++ {
		virtualKey := fmt.Sprintf("%s:%d", nodeID, i)
		hash := chr.hash(virtualKey)
		chr.nodes[hash] = nodeID
	}

	chr.rebuildSortedKeys()
}

// RemoveNode removes a node from the consistent hash ring
func (chr *ConsistentHashRing) RemoveNode(nodeID string) {
	chr.mu.Lock()
	defer chr.mu.Unlock()

	// Remove all virtual nodes
	for hash, node := range chr.nodes {
		if node == nodeID {
			delete(chr.nodes, hash)
		}
	}

	chr.rebuildSortedKeys()
}

// hash generates a hash for a key
func (chr *ConsistentHashRing) hash(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32()
}

// rebuildSortedKeys rebuilds the sorted keys slice
func (chr *ConsistentHashRing) rebuildSortedKeys() {
	chr.sortedKeys = make([]uint32, 0, len(chr.nodes))
	for hash := range chr.nodes {
		chr.sortedKeys = append(chr.sortedKeys, hash)
	}
	sort.Slice(chr.sortedKeys, func(i, j int) bool {
		return chr.sortedKeys[i] < chr.sortedKeys[j]
	})
}

// AcquireLock acquires a distributed lock
func (dlm *DistributedLockManager) AcquireLock(ctx context.Context, key string) (*DistributedLock, error) {
	lockValue := fmt.Sprintf("%d", time.Now().UnixNano())

	for i := 0; i < dlm.maxRetries; i++ {
		acquired, err := dlm.redisClient.SetNX(ctx, key, lockValue, dlm.lockTTL).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to acquire lock: %v", err)
		}

		if acquired {
			return &DistributedLock{
				Key:        key,
				Value:      lockValue,
				TTL:        dlm.lockTTL,
				AcquiredAt: time.Now(),
			}, nil
		}

		// Wait before retrying
		time.Sleep(dlm.retryDelay)
	}

	return nil, fmt.Errorf("failed to acquire lock after %d retries", dlm.maxRetries)
}

// ReleaseLock releases a distributed lock
func (dlm *DistributedLockManager) ReleaseLock(ctx context.Context, lock *DistributedLock) error {
	// Use Lua script to ensure atomic release
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`

	result, err := dlm.redisClient.Eval(ctx, script, []string{lock.Key}, lock.Value).Result()
	if err != nil {
		return fmt.Errorf("failed to release lock: %v", err)
	}

	if result.(int64) == 0 {
		return fmt.Errorf("lock was not owned or already expired")
	}

	return nil
}

// Background service methods
func (mcs *MeetingClusterService) heartbeatLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mcs.sendHeartbeat()
		case <-mcs.shutdownChan:
			return
		}
	}
}

func (mcs *MeetingClusterService) stateSync() {
	ticker := time.NewTicker(mcs.stateManager.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mcs.syncMeetingStates()
		case <-mcs.shutdownChan:
			return
		}
	}
}

func (mcs *MeetingClusterService) healthMonitoring() {
	ticker := time.NewTicker(mcs.healthChecker.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mcs.checkClusterHealth()
		case <-mcs.shutdownChan:
			return
		}
	}
}

func (mcs *MeetingClusterService) loadBalancing() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mcs.updateLoadBalancer()
		case <-mcs.shutdownChan:
			return
		}
	}
}

// Helper methods
func (mcs *MeetingClusterService) registerNode() {
	nodeKey := fmt.Sprintf("cluster:node:%s", mcs.nodeID)
	nodeJSON, _ := json.Marshal(mcs.nodeInfo)

	ctx := context.Background()
	mcs.redisClient.Set(ctx, nodeKey, nodeJSON, time.Minute*5)
	mcs.redisClient.SAdd(ctx, "cluster:nodes", mcs.nodeID)

	facades.Log().Info("Node registered in cluster", map[string]interface{}{
		"node_id": mcs.nodeID,
		"address": mcs.nodeInfo.Address,
		"port":    mcs.nodeInfo.Port,
	})
}

func (mcs *MeetingClusterService) sendHeartbeat() {
	mcs.nodeInfo.LastHeartbeat = time.Now()
	mcs.nodeInfo.CurrentLoad = len(mcs.activeMeetings)

	// Update node metrics
	mcs.updateNodeMetrics()

	nodeKey := fmt.Sprintf("cluster:node:%s", mcs.nodeID)
	nodeJSON, _ := json.Marshal(mcs.nodeInfo)

	ctx := context.Background()
	mcs.redisClient.Set(ctx, nodeKey, nodeJSON, time.Minute*5)
}

func (mcs *MeetingClusterService) updateNodeMetrics() {
	// Implementation would collect actual system metrics
	mcs.nodeInfo.CPUUsage = 45.2
	mcs.nodeInfo.MemoryUsage = 1024.5
	mcs.nodeInfo.NetworkBandwidth = 100.0
}

func (mcs *MeetingClusterService) syncMeetingStates() {
	// Implementation would sync meeting states across nodes
}

func (mcs *MeetingClusterService) checkClusterHealth() {
	// Implementation would check health of all cluster nodes
}

func (mcs *MeetingClusterService) updateLoadBalancer() {
	// Implementation would update load balancer with current node states
}

func (mcs *MeetingClusterService) selectReplicaNodes(primary *ClusterNode, count int) []string {
	// Implementation would select replica nodes
	return []string{}
}

func (mcs *MeetingClusterService) isReplicaNode(meeting *DistributedMeeting, nodeID string) bool {
	for _, replica := range meeting.ReplicaNodes {
		if replica == nodeID {
			return true
		}
	}
	return false
}

func (mcs *MeetingClusterService) generateLoadBalanceKey(meetingID string) string {
	return fmt.Sprintf("lb:%s:%d", meetingID, time.Now().Unix())
}

func (mcs *MeetingClusterService) broadcastMeetingEvent(eventType, meetingID string, data map[string]interface{}) {
	event := map[string]interface{}{
		"type":       eventType,
		"meeting_id": meetingID,
		"node_id":    mcs.nodeID,
		"timestamp":  time.Now(),
		"data":       data,
	}

	eventJSON, _ := json.Marshal(event)
	ctx := context.Background()
	mcs.redisClient.Publish(ctx, "cluster:events", eventJSON)
}

// State management methods
func (dsm *DistributedStateManager) SetMeetingState(meetingID string, meeting *DistributedMeeting) error {
	key := dsm.keyPrefix + meetingID
	meetingJSON, _ := json.Marshal(meeting)

	ctx := context.Background()
	return dsm.redisClient.Set(ctx, key, meetingJSON, time.Hour).Err()
}

func (dsm *DistributedStateManager) GetMeetingState(meetingID string) (*DistributedMeeting, error) {
	key := dsm.keyPrefix + meetingID

	ctx := context.Background()
	result, err := dsm.redisClient.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	var meeting DistributedMeeting
	err = json.Unmarshal([]byte(result), &meeting)
	if err != nil {
		return nil, err
	}

	return &meeting, nil
}

func (dsm *DistributedStateManager) DeleteMeetingState(meetingID string) error {
	key := dsm.keyPrefix + meetingID

	ctx := context.Background()
	return dsm.redisClient.Del(ctx, key).Err()
}

// Shutdown gracefully shuts down the cluster service
func (mcs *MeetingClusterService) Shutdown() {
	close(mcs.shutdownChan)

	// Deregister node
	ctx := context.Background()
	mcs.redisClient.SRem(ctx, "cluster:nodes", mcs.nodeID)
	mcs.redisClient.Del(ctx, fmt.Sprintf("cluster:node:%s", mcs.nodeID))

	facades.Log().Info("Meeting cluster service shut down", map[string]interface{}{
		"node_id": mcs.nodeID,
	})
}
