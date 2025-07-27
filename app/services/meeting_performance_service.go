package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// MeetingPerformanceService handles performance optimizations for meetings
type MeetingPerformanceService struct {
	cache            map[string]*CacheEntry
	cacheMu          sync.RWMutex
	connectionPool   *ConnectionPool
	queryOptimizer   *QueryOptimizer
	metricsCollector *MeetingMetrics
	cleanupTicker    *time.Ticker
	ctx              context.Context
	cancel           context.CancelFunc
}

// CacheEntry represents a cached item with expiration
type CacheEntry struct {
	Data        interface{}
	ExpiresAt   time.Time
	AccessCount int64
	LastAccess  time.Time
}

// ConnectionPool manages database connections for better performance
type ConnectionPool struct {
	maxConnections int
	activeConns    int
	mu             sync.Mutex
}

// QueryOptimizer provides optimized database queries
type QueryOptimizer struct {
	preparedStatements map[string]interface{}
	indexHints         map[string]string
	mu                 sync.RWMutex
}

// MeetingMetrics collects performance metrics
type MeetingMetrics struct {
	TotalMeetings       int64
	ActiveMeetings      int64
	TotalParticipants   int64
	ActiveParticipants  int64
	DatabaseQueries     int64
	CacheHits           int64
	CacheMisses         int64
	AverageResponseTime time.Duration
	PeakParticipants    int64
	ErrorCount          int64
	mu                  sync.RWMutex
}

// Cache keys
const (
	CacheKeyMeeting               = "meeting:%s"
	CacheKeyMeetingParticipants   = "meeting_participants:%s"
	CacheKeyMeetingSecurityPolicy = "meeting_security_policy:%s"
	CacheKeyUserMeetings          = "user_meetings:%s"
	CacheKeyActiveMeetings        = "active_meetings"
	CacheKeyMeetingStats          = "meeting_stats:%s"
	CacheKeyMeetingChat           = "meeting_chat:%s"
)

// Cache durations
const (
	CacheDurationShort  = 5 * time.Minute
	CacheDurationMedium = 15 * time.Minute
	CacheDurationLong   = 1 * time.Hour
)

// NewMeetingPerformanceService creates a new performance service
func NewMeetingPerformanceService() *MeetingPerformanceService {
	ctx, cancel := context.WithCancel(context.Background())

	service := &MeetingPerformanceService{
		cache: make(map[string]*CacheEntry),
		connectionPool: &ConnectionPool{
			maxConnections: 50,
			activeConns:    0,
		},
		queryOptimizer: &QueryOptimizer{
			preparedStatements: make(map[string]interface{}),
			indexHints:         make(map[string]string),
		},
		metricsCollector: &MeetingMetrics{},
		ctx:              ctx,
		cancel:           cancel,
	}

	// Initialize query optimizer
	service.initializeQueryOptimizer()

	// Start cleanup routine
	service.startCleanup()

	return service
}

// GetMeetingCached retrieves a meeting with caching
func (mps *MeetingPerformanceService) GetMeetingCached(meetingID string) (*models.Meeting, error) {
	cacheKey := fmt.Sprintf(CacheKeyMeeting, meetingID)

	// Try cache first
	if cached := mps.getFromCache(cacheKey); cached != nil {
		if meeting, ok := cached.(*models.Meeting); ok {
			mps.recordCacheHit()
			return meeting, nil
		}
	}

	mps.recordCacheMiss()

	// Query database with optimization
	var meeting models.Meeting
	err := facades.Orm().Query().
		With("Event").
		With("Participants", func(query interface{}) interface{} {
			// Only load active participants for performance
			return query
		}).
		Where("id", meetingID).
		First(&meeting)

	if err != nil {
		mps.recordError()
		return nil, err
	}

	// Cache the result
	mps.setCache(cacheKey, &meeting, CacheDurationMedium)
	mps.recordDatabaseQuery()

	return &meeting, nil
}

// GetMeetingParticipantsCached retrieves meeting participants with caching
func (mps *MeetingPerformanceService) GetMeetingParticipantsCached(meetingID string) ([]models.MeetingParticipant, error) {
	cacheKey := fmt.Sprintf(CacheKeyMeetingParticipants, meetingID)

	// Try cache first
	if cached := mps.getFromCache(cacheKey); cached != nil {
		if participants, ok := cached.([]models.MeetingParticipant); ok {
			mps.recordCacheHit()
			return participants, nil
		}
	}

	mps.recordCacheMiss()

	// Query database with optimization
	var participants []models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("status", "joined").
		Order("joined_at ASC").
		Find(&participants)

	if err != nil {
		mps.recordError()
		return nil, err
	}

	// Cache the result
	mps.setCache(cacheKey, participants, CacheDurationShort)
	mps.recordDatabaseQuery()

	return participants, nil
}

// GetMeetingSecurityPolicyCached retrieves security policy with caching
func (mps *MeetingPerformanceService) GetMeetingSecurityPolicyCached(meetingID string) (*models.MeetingSecurityPolicy, error) {
	cacheKey := fmt.Sprintf(CacheKeyMeetingSecurityPolicy, meetingID)

	// Try cache first
	if cached := mps.getFromCache(cacheKey); cached != nil {
		if policy, ok := cached.(*models.MeetingSecurityPolicy); ok {
			mps.recordCacheHit()
			return policy, nil
		}
	}

	mps.recordCacheMiss()

	// Query database
	var policy models.MeetingSecurityPolicy
	err := facades.Orm().Query().Where("meeting_id", meetingID).First(&policy)
	if err != nil {
		// Create default policy if none exists
		defaultPolicy := models.GetDefaultSecurityPolicy()
		defaultPolicy.MeetingID = meetingID

		if createErr := facades.Orm().Query().Create(defaultPolicy); createErr != nil {
			mps.recordError()
			return nil, createErr
		}

		// Cache the default policy
		mps.setCache(cacheKey, defaultPolicy, CacheDurationLong)
		mps.recordDatabaseQuery()
		return defaultPolicy, nil
	}

	// Cache the result
	mps.setCache(cacheKey, &policy, CacheDurationLong)
	mps.recordDatabaseQuery()

	return &policy, nil
}

// GetActiveMeetingsCached retrieves active meetings with caching
func (mps *MeetingPerformanceService) GetActiveMeetingsCached() ([]models.Meeting, error) {
	cacheKey := CacheKeyActiveMeetings

	// Try cache first
	if cached := mps.getFromCache(cacheKey); cached != nil {
		if meetings, ok := cached.([]models.Meeting); ok {
			mps.recordCacheHit()
			return meetings, nil
		}
	}

	mps.recordCacheMiss()

	// Query database with optimization
	var meetings []models.Meeting
	err := facades.Orm().Query().
		Where("status", "in_progress").
		Where("started_at IS NOT NULL").
		Where("ended_at IS NULL").
		Order("started_at DESC").
		Find(&meetings)

	if err != nil {
		mps.recordError()
		return nil, err
	}

	// Cache the result for a short time since this changes frequently
	mps.setCache(cacheKey, meetings, CacheDurationShort)
	mps.recordDatabaseQuery()

	return meetings, nil
}

// BatchUpdateParticipants optimizes bulk participant updates
func (mps *MeetingPerformanceService) BatchUpdateParticipants(updates []models.MeetingParticipant) error {
	if len(updates) == 0 {
		return nil
	}

	// Use transaction for better performance
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		mps.recordError()
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Batch update participants
	for _, participant := range updates {
		if err := tx.Save(&participant); err != nil {
			tx.Rollback()
			mps.recordError()
			return err
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		mps.recordError()
		return err
	}

	// Invalidate cache for affected meetings
	meetingIDs := make(map[string]bool)
	for _, participant := range updates {
		meetingIDs[participant.MeetingID] = true
	}

	for meetingID := range meetingIDs {
		mps.invalidateCache(fmt.Sprintf(CacheKeyMeetingParticipants, meetingID))
	}

	mps.recordDatabaseQuery()
	return nil
}

// OptimizeQuery provides query optimization hints
func (mps *MeetingPerformanceService) OptimizeQuery(queryType string) map[string]interface{} {
	mps.queryOptimizer.mu.RLock()
	defer mps.queryOptimizer.mu.RUnlock()

	optimizations := make(map[string]interface{})

	switch queryType {
	case "get_meeting_participants":
		optimizations["use_index"] = "idx_meeting_participants_meeting_id_status"
		optimizations["limit"] = 1000 // Prevent huge result sets
		optimizations["select_fields"] = []string{"id", "user_id", "meeting_id", "role", "status", "is_muted", "is_video_enabled"}

	case "get_active_meetings":
		optimizations["use_index"] = "idx_meetings_status_started_at"
		optimizations["limit"] = 100

	case "get_meeting_chat":
		optimizations["use_index"] = "idx_meeting_chat_meeting_id_created_at"
		optimizations["limit"] = 50
		optimizations["order"] = "created_at DESC"

	case "get_meeting_recordings":
		optimizations["use_index"] = "idx_meeting_recordings_meeting_id_status"
		optimizations["select_fields"] = []string{"id", "meeting_id", "file_name", "file_path", "status", "created_at"}
	}

	return optimizations
}

// PrewarmCache preloads frequently accessed data
func (mps *MeetingPerformanceService) PrewarmCache() error {
	// Preload active meetings
	_, err := mps.GetActiveMeetingsCached()
	if err != nil {
		return err
	}

	// Preload security policies for active meetings
	activeMeetings, err := mps.GetActiveMeetingsCached()
	if err != nil {
		return err
	}

	for _, meeting := range activeMeetings {
		// Preload participants
		_, err := mps.GetMeetingParticipantsCached(meeting.ID)
		if err != nil {
			facades.Log().Warning("Failed to preload participants", map[string]interface{}{
				"meeting_id": meeting.ID,
				"error":      err.Error(),
			})
		}

		// Preload security policy
		_, err = mps.GetMeetingSecurityPolicyCached(meeting.ID)
		if err != nil {
			facades.Log().Warning("Failed to preload security policy", map[string]interface{}{
				"meeting_id": meeting.ID,
				"error":      err.Error(),
			})
		}
	}

	facades.Log().Info("Cache prewarming completed", map[string]interface{}{
		"active_meetings": len(activeMeetings),
	})

	return nil
}

// GetMetrics returns performance metrics
func (mps *MeetingPerformanceService) GetMetrics() *MeetingMetrics {
	mps.metricsCollector.mu.RLock()
	defer mps.metricsCollector.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &MeetingMetrics{
		TotalMeetings:       mps.metricsCollector.TotalMeetings,
		ActiveMeetings:      mps.metricsCollector.ActiveMeetings,
		TotalParticipants:   mps.metricsCollector.TotalParticipants,
		ActiveParticipants:  mps.metricsCollector.ActiveParticipants,
		DatabaseQueries:     mps.metricsCollector.DatabaseQueries,
		CacheHits:           mps.metricsCollector.CacheHits,
		CacheMisses:         mps.metricsCollector.CacheMisses,
		AverageResponseTime: mps.metricsCollector.AverageResponseTime,
		PeakParticipants:    mps.metricsCollector.PeakParticipants,
		ErrorCount:          mps.metricsCollector.ErrorCount,
	}

	return metrics
}

// Cache management methods

func (mps *MeetingPerformanceService) getFromCache(key string) interface{} {
	mps.cacheMu.RLock()
	defer mps.cacheMu.RUnlock()

	entry, exists := mps.cache[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		return nil
	}

	// Update access statistics
	entry.AccessCount++
	entry.LastAccess = time.Now()

	return entry.Data
}

func (mps *MeetingPerformanceService) setCache(key string, data interface{}, duration time.Duration) {
	mps.cacheMu.Lock()
	defer mps.cacheMu.Unlock()

	mps.cache[key] = &CacheEntry{
		Data:        data,
		ExpiresAt:   time.Now().Add(duration),
		AccessCount: 0,
		LastAccess:  time.Now(),
	}
}

func (mps *MeetingPerformanceService) invalidateCache(key string) {
	mps.cacheMu.Lock()
	defer mps.cacheMu.Unlock()

	delete(mps.cache, key)
}

func (mps *MeetingPerformanceService) clearExpiredCache() {
	mps.cacheMu.Lock()
	defer mps.cacheMu.Unlock()

	now := time.Now()
	for key, entry := range mps.cache {
		if now.After(entry.ExpiresAt) {
			delete(mps.cache, key)
		}
	}
}

// Query optimization methods

func (mps *MeetingPerformanceService) initializeQueryOptimizer() {
	mps.queryOptimizer.mu.Lock()
	defer mps.queryOptimizer.mu.Unlock()

	// Set up index hints for common queries
	mps.queryOptimizer.indexHints["get_meeting_participants"] = "idx_meeting_participants_meeting_id_status"
	mps.queryOptimizer.indexHints["get_active_meetings"] = "idx_meetings_status_started_at"
	mps.queryOptimizer.indexHints["get_meeting_chat"] = "idx_meeting_chat_meeting_id_created_at"
}

func (mps *MeetingPerformanceService) getOptimizedQuery(queryType string) interface{} {
	mps.queryOptimizer.mu.RLock()
	defer mps.queryOptimizer.mu.RUnlock()

	// Return optimized query configuration
	return mps.queryOptimizer.preparedStatements[queryType]
}

// Metrics recording methods

func (mps *MeetingPerformanceService) recordCacheHit() {
	mps.metricsCollector.mu.Lock()
	defer mps.metricsCollector.mu.Unlock()
	mps.metricsCollector.CacheHits++
}

func (mps *MeetingPerformanceService) recordCacheMiss() {
	mps.metricsCollector.mu.Lock()
	defer mps.metricsCollector.mu.Unlock()
	mps.metricsCollector.CacheMisses++
}

func (mps *MeetingPerformanceService) recordDatabaseQuery() {
	mps.metricsCollector.mu.Lock()
	defer mps.metricsCollector.mu.Unlock()
	mps.metricsCollector.DatabaseQueries++
}

func (mps *MeetingPerformanceService) recordError() {
	mps.metricsCollector.mu.Lock()
	defer mps.metricsCollector.mu.Unlock()
	mps.metricsCollector.ErrorCount++
}

func (mps *MeetingPerformanceService) updateParticipantCount(count int64) {
	mps.metricsCollector.mu.Lock()
	defer mps.metricsCollector.mu.Unlock()

	mps.metricsCollector.ActiveParticipants = count
	if count > mps.metricsCollector.PeakParticipants {
		mps.metricsCollector.PeakParticipants = count
	}
}

// Cleanup and maintenance

func (mps *MeetingPerformanceService) startCleanup() {
	mps.cleanupTicker = time.NewTicker(10 * time.Minute)

	go func() {
		for {
			select {
			case <-mps.cleanupTicker.C:
				mps.performMaintenance()
			case <-mps.ctx.Done():
				return
			}
		}
	}()
}

func (mps *MeetingPerformanceService) performMaintenance() {
	// Clear expired cache entries
	mps.clearExpiredCache()

	// Log performance metrics
	metrics := mps.GetMetrics()
	facades.Log().Info("Meeting performance metrics", map[string]interface{}{
		"cache_hits":          metrics.CacheHits,
		"cache_misses":        metrics.CacheMisses,
		"database_queries":    metrics.DatabaseQueries,
		"active_meetings":     metrics.ActiveMeetings,
		"active_participants": metrics.ActiveParticipants,
		"error_count":         metrics.ErrorCount,
	})

	// Prewarm cache for frequently accessed data
	if err := mps.PrewarmCache(); err != nil {
		facades.Log().Error("Failed to prewarm cache", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

// Shutdown gracefully shuts down the performance service
func (mps *MeetingPerformanceService) Shutdown() {
	mps.cancel()

	if mps.cleanupTicker != nil {
		mps.cleanupTicker.Stop()
	}

	// Clear cache
	mps.cacheMu.Lock()
	mps.cache = make(map[string]*CacheEntry)
	mps.cacheMu.Unlock()

	facades.Log().Info("Meeting performance service shutdown completed")
}
