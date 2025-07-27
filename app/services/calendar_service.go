package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"goravel/app/models"
	"goravel/app/notifications"

	"github.com/goravel/framework/facades"
)

type CalendarService struct {
	emailService *EmailService
}

func NewCalendarService() *CalendarService {
	return &CalendarService{
		emailService: NewEmailService(),
	}
}

// ScheduleReminders schedules reminders for a calendar event
func (cs *CalendarService) ScheduleReminders(event *models.CalendarEvent) error {
	if event.ReminderSettings == "" {
		return nil // No reminders configured
	}

	// Parse reminder settings
	var reminderSettings map[string]int
	if err := json.Unmarshal([]byte(event.ReminderSettings), &reminderSettings); err != nil {
		return fmt.Errorf("invalid reminder settings: %v", err)
	}

	// Get event participants
	var participants []models.EventParticipant
	err := facades.Orm().Query().Where("event_id = ? AND send_reminder = ?", event.ID, true).Find(&participants)
	if err != nil {
		return fmt.Errorf("failed to get participants: %v", err)
	}

	// Create reminders for each participant and type
	for _, participant := range participants {
		for reminderType, minutesBefore := range reminderSettings {
			scheduledAt := event.StartTime.Add(-time.Duration(minutesBefore) * time.Minute)

			// Only create future reminders
			if scheduledAt.After(time.Now()) {
				reminder := models.EventReminder{
					EventID:       event.ID,
					UserID:        participant.UserID,
					Type:          reminderType,
					MinutesBefore: minutesBefore,
					ScheduledAt:   scheduledAt,
					Status:        "pending",
				}

				if err := facades.Orm().Query().Create(&reminder); err != nil {
					facades.Log().Error("Failed to create reminder", map[string]interface{}{
						"event_id": event.ID,
						"user_id":  participant.UserID,
						"type":     reminderType,
						"error":    err.Error(),
					})
				}
			}
		}
	}

	return nil
}

// ProcessDueReminders processes reminders that are due to be sent
func (cs *CalendarService) ProcessDueReminders() error {
	var reminders []models.EventReminder
	err := facades.Orm().Query().
		Where("status = ? AND scheduled_at <= ?", "pending", time.Now()).
		With("Event").With("User").
		Find(&reminders)
	if err != nil {
		return fmt.Errorf("failed to get due reminders: %v", err)
	}

	for _, reminder := range reminders {
		if err := cs.sendReminder(&reminder); err != nil {
			facades.Log().Error("Failed to send reminder", map[string]interface{}{
				"reminder_id": reminder.ID,
				"error":       err.Error(),
			})

			// Mark reminder as failed
			reminder.Status = "failed"
			reminder.ErrorMessage = err.Error()
			facades.Orm().Query().Save(&reminder)
		} else {
			// Mark reminder as sent
			now := time.Now()
			reminder.Status = "sent"
			reminder.Sent = true
			reminder.SentAt = &now
			facades.Orm().Query().Save(&reminder)
		}
	}

	return nil
}

// sendReminder sends a reminder based on its type
func (cs *CalendarService) sendReminder(reminder *models.EventReminder) error {
	switch reminder.Type {
	case "email":
		return cs.sendEmailReminder(reminder)
	case "push":
		return cs.sendPushReminder(reminder)
	case "sms":
		return cs.sendSMSReminder(reminder)
	default:
		return fmt.Errorf("unknown reminder type: %s", reminder.Type)
	}
}

// sendEmailReminder sends an email reminder
func (cs *CalendarService) sendEmailReminder(reminder *models.EventReminder) error {
	subject := fmt.Sprintf("Reminder: %s", reminder.Event.Title)
	body := fmt.Sprintf(`
		<h2>Event Reminder</h2>
		<p>This is a reminder for your upcoming event:</p>
		<ul>
			<li><strong>Event:</strong> %s</li>
			<li><strong>Time:</strong> %s</li>
			<li><strong>Location:</strong> %s</li>
		</ul>
		<p>Event starts in %d minutes.</p>
	`, reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04"), reminder.Event.Location, reminder.MinutesBefore)

	return cs.emailService.SendEmail(reminder.User.Email, subject, body, body)
}

// sendPushReminder sends a push notification reminder
func (cs *CalendarService) sendPushReminder(reminder *models.EventReminder) error {
	// Create a notification for the event reminder
	notificationService := NewNotificationService()

	// Create notification using BaseNotification
	notification := notifications.NewBaseNotification()
	notification.SetType("event_reminder")
	notification.SetTitle("Event Reminder")
	notification.SetBody(fmt.Sprintf("Reminder: %s is starting at %s", reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04")))
	notification.SetChannels([]string{"push"})
	notification.SetActionURL("/calendar").SetActionText("View Event")
	notification.AddData("event_title", reminder.Event.Title)
	notification.AddData("event_time", reminder.Event.StartTime)

	// Send push notification
	ctx := context.Background()
	err := notificationService.SendNow(ctx, notification, reminder.User)
	if err != nil {
		facades.Log().Error("Failed to send push reminder", map[string]interface{}{
			"user_id": reminder.UserID,
			"event":   reminder.Event.Title,
			"error":   err.Error(),
		})
		return err
	}

	facades.Log().Info("Push reminder sent successfully", map[string]interface{}{
		"user_id": reminder.UserID,
		"event":   reminder.Event.Title,
	})

	return nil
}

// sendSMSReminder sends an SMS reminder
func (cs *CalendarService) sendSMSReminder(reminder *models.EventReminder) error {
	// Create a notification for the event reminder
	notificationService := NewNotificationService()

	// Create notification using BaseNotification
	notification := notifications.NewBaseNotification()
	notification.SetType("event_reminder")
	notification.SetTitle("Event Reminder")
	notification.SetBody(fmt.Sprintf("Reminder: %s is starting at %s", reminder.Event.Title, reminder.Event.StartTime.Format("2006-01-02 15:04")))
	notification.SetChannels([]string{"sms"})
	notification.AddData("event_title", reminder.Event.Title)
	notification.AddData("event_time", reminder.Event.StartTime)

	// Send SMS notification
	ctx := context.Background()
	err := notificationService.SendNow(ctx, notification, reminder.User)
	if err != nil {
		facades.Log().Error("Failed to send SMS reminder", map[string]interface{}{
			"user_id": reminder.UserID,
			"event":   reminder.Event.Title,
			"error":   err.Error(),
		})
		return err
	}

	facades.Log().Info("SMS reminder sent successfully", map[string]interface{}{
		"user_id": reminder.UserID,
		"event":   reminder.Event.Title,
	})

	return nil
}

// CheckConflicts checks for scheduling conflicts
func (cs *CalendarService) CheckConflicts(startTime, endTime time.Time, userIDs []string, excludeEventID string) (map[string]interface{}, error) {
	// Build query for conflicting events
	query := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id IN ?", userIDs).
		Where("(start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?) OR (start_time >= ? AND end_time <= ?)",
			endTime, startTime, endTime, startTime, startTime, endTime)

	// Exclude specific event if provided
	if excludeEventID != "" {
		query = query.Where("calendar_events.id != ?", excludeEventID)
	}

	var conflictingEvents []models.CalendarEvent
	err := query.With("Participants.User").Find(&conflictingEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to check conflicts: %v", err)
	}

	// Group conflicts by user
	conflictsByUser := make(map[string][]models.CalendarEvent)
	for _, event := range conflictingEvents {
		for _, participant := range event.Participants {
			for _, userID := range userIDs {
				if userID == participant.UserID {
					conflictsByUser[participant.UserID] = append(conflictsByUser[participant.UserID], event)
					break
				}
			}
		}
	}

	return map[string]interface{}{
		"has_conflicts":      len(conflictingEvents) > 0,
		"conflicts_by_user":  conflictsByUser,
		"total_conflicts":    len(conflictingEvents),
		"conflicting_events": conflictingEvents,
	}, nil
}

// GenerateRecurringEvents generates recurring event instances
func (cs *CalendarService) GenerateRecurringEvents(event *models.CalendarEvent) error {
	if !event.IsRecurring || event.RecurrenceRule == "" {
		return nil
	}

	// Parse RRULE and generate instances
	// This is a simplified implementation - in production, you'd use a proper RRULE parser
	instances := cs.parseRRULE(event)

	for _, instance := range instances {
		// Check if instance already exists
		var existingInstance models.CalendarEvent
		err := facades.Orm().Query().Where("parent_event_id = ? AND start_time = ?", event.ID, instance.StartTime).First(&existingInstance)
		if err == nil {
			continue // Instance already exists
		}

		// Create new instance
		instance.ParentEventID = &event.ID
		instance.TenantID = event.TenantID
		instance.CreatedBy = event.CreatedBy

		if err := facades.Orm().Query().Create(&instance); err != nil {
			facades.Log().Error("Failed to create recurring instance", map[string]interface{}{
				"parent_event_id": event.ID,
				"start_time":      instance.StartTime,
				"error":           err.Error(),
			})
		}
	}

	return nil
}

// parseRRULE parses RRULE and generates event instances
func (cs *CalendarService) parseRRULE(event *models.CalendarEvent) []models.CalendarEvent {
	// Enhanced RRULE parser supporting common recurrence patterns
	// For production use, consider github.com/teambition/rrule-go or similar

	var instances []models.CalendarEvent

	if event.RecurrenceRule == "" {
		return instances
	}

	// Parse RRULE string
	rrule, err := cs.parseRRULEString(event.RecurrenceRule)
	if err != nil {
		facades.Log().Error("Failed to parse RRULE", map[string]interface{}{
			"event_id":        event.ID,
			"recurrence_rule": event.RecurrenceRule,
			"error":           err.Error(),
		})
		return instances
	}

	// Generate instances based on the parsed rule
	instances = cs.generateRecurrenceInstances(event, rrule)

	facades.Log().Info("Generated recurring instances", map[string]interface{}{
		"event_id":       event.ID,
		"instance_count": len(instances),
		"frequency":      rrule.Frequency,
		"interval":       rrule.Interval,
	})

	return instances
}

// RRULERule represents a parsed RRULE with enhanced support
type RRULERule struct {
	Frequency  string     // DAILY, WEEKLY, MONTHLY, YEARLY
	Interval   int        // Interval between occurrences
	Count      int        // Number of occurrences (0 = unlimited)
	Until      *time.Time // End date
	ByDay      []string   // Days of week (MO, TU, WE, etc.)
	ByMonth    []int      // Months (1-12)
	ByMonthDay []int      // Days of month (1-31)
	ByYearDay  []int      // Days of year (1-366)
	ByWeekNo   []int      // Week numbers (1-53)
	ByHour     []int      // Hours (0-23)
	ByMinute   []int      // Minutes (0-59)
	BySecond   []int      // Seconds (0-59)
	BySetPos   []int      // Set positions (-366 to 366)
	WeekStart  string     // Week start day (MO, TU, etc.)
}

// parseRRULEString parses an RRULE string into a structured format with enhanced validation
func (cs *CalendarService) parseRRULEString(rruleStr string) (*RRULERule, error) {
	rule := &RRULERule{
		Interval:  1,    // Default interval
		WeekStart: "MO", // Default week start
	}

	// Remove RRULE: prefix if present
	if strings.HasPrefix(rruleStr, "RRULE:") {
		rruleStr = strings.TrimPrefix(rruleStr, "RRULE:")
	}

	// Split by semicolon
	parts := strings.Split(rruleStr, ";")

	for _, part := range parts {
		keyValue := strings.Split(part, "=")
		if len(keyValue) != 2 {
			continue
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		switch key {
		case "FREQ":
			if !cs.isValidFrequency(value) {
				return nil, fmt.Errorf("invalid frequency: %s", value)
			}
			rule.Frequency = value
		case "INTERVAL":
			if interval, err := strconv.Atoi(value); err == nil && interval > 0 {
				rule.Interval = interval
			} else {
				return nil, fmt.Errorf("invalid interval: %s", value)
			}
		case "COUNT":
			if count, err := strconv.Atoi(value); err == nil && count > 0 {
				rule.Count = count
			} else {
				return nil, fmt.Errorf("invalid count: %s", value)
			}
		case "UNTIL":
			until, err := cs.parseUntilDate(value)
			if err != nil {
				return nil, fmt.Errorf("invalid until date: %s", value)
			}
			rule.Until = until
		case "BYDAY":
			days := strings.Split(value, ",")
			for _, day := range days {
				if !cs.isValidByDay(day) {
					return nil, fmt.Errorf("invalid BYDAY value: %s", day)
				}
			}
			rule.ByDay = days
		case "BYMONTH":
			months, err := cs.parseIntList(value, 1, 12)
			if err != nil {
				return nil, fmt.Errorf("invalid BYMONTH: %s", value)
			}
			rule.ByMonth = months
		case "BYMONTHDAY":
			days, err := cs.parseIntList(value, -31, 31)
			if err != nil {
				return nil, fmt.Errorf("invalid BYMONTHDAY: %s", value)
			}
			rule.ByMonthDay = days
		case "BYYEARDAY":
			days, err := cs.parseIntList(value, -366, 366)
			if err != nil {
				return nil, fmt.Errorf("invalid BYYEARDAY: %s", value)
			}
			rule.ByYearDay = days
		case "BYWEEKNO":
			weeks, err := cs.parseIntList(value, -53, 53)
			if err != nil {
				return nil, fmt.Errorf("invalid BYWEEKNO: %s", value)
			}
			rule.ByWeekNo = weeks
		case "BYHOUR":
			hours, err := cs.parseIntList(value, 0, 23)
			if err != nil {
				return nil, fmt.Errorf("invalid BYHOUR: %s", value)
			}
			rule.ByHour = hours
		case "BYMINUTE":
			minutes, err := cs.parseIntList(value, 0, 59)
			if err != nil {
				return nil, fmt.Errorf("invalid BYMINUTE: %s", value)
			}
			rule.ByMinute = minutes
		case "BYSECOND":
			seconds, err := cs.parseIntList(value, 0, 59)
			if err != nil {
				return nil, fmt.Errorf("invalid BYSECOND: %s", value)
			}
			rule.BySecond = seconds
		case "BYSETPOS":
			positions, err := cs.parseIntList(value, -366, 366)
			if err != nil {
				return nil, fmt.Errorf("invalid BYSETPOS: %s", value)
			}
			rule.BySetPos = positions
		case "WKST":
			if !cs.isValidWeekDay(value) {
				return nil, fmt.Errorf("invalid WKST: %s", value)
			}
			rule.WeekStart = value
		}
	}

	// Validate required fields and combinations
	if rule.Frequency == "" {
		return nil, fmt.Errorf("FREQ is required in RRULE")
	}

	// Validate COUNT and UNTIL are mutually exclusive
	if rule.Count > 0 && rule.Until != nil {
		return nil, fmt.Errorf("COUNT and UNTIL cannot both be specified")
	}

	return rule, nil
}

// Helper validation functions
func (cs *CalendarService) isValidFrequency(freq string) bool {
	validFreqs := []string{"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}
	for _, valid := range validFreqs {
		if freq == valid {
			return true
		}
	}
	return false
}

func (cs *CalendarService) isValidWeekDay(day string) bool {
	validDays := []string{"MO", "TU", "WE", "TH", "FR", "SA", "SU"}
	for _, valid := range validDays {
		if day == valid {
			return true
		}
	}
	return false
}

func (cs *CalendarService) isValidByDay(byDay string) bool {
	// BYDAY can be: MO, TU, WE, TH, FR, SA, SU
	// Or with ordinal: 1MO, -1FR, 2TU, etc.
	if len(byDay) < 2 {
		return false
	}

	// Extract day part (last 2 characters)
	day := byDay[len(byDay)-2:]
	if !cs.isValidWeekDay(day) {
		return false
	}

	// If there's an ordinal prefix, validate it
	if len(byDay) > 2 {
		ordinal := byDay[:len(byDay)-2]
		if ordinalInt, err := strconv.Atoi(ordinal); err != nil || ordinalInt == 0 || ordinalInt < -53 || ordinalInt > 53 {
			return false
		}
	}

	return true
}

func (cs *CalendarService) parseUntilDate(dateStr string) (*time.Time, error) {
	// Try different date formats
	formats := []string{
		"20060102T150405Z",
		"20060102T150405",
		"20060102",
	}

	for _, format := range formats {
		if parsed, err := time.Parse(format, dateStr); err == nil {
			return &parsed, nil
		}
	}

	return nil, fmt.Errorf("unable to parse date: %s", dateStr)
}

func (cs *CalendarService) parseIntList(value string, min, max int) ([]int, error) {
	var result []int
	parts := strings.Split(value, ",")

	for _, part := range parts {
		num, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		if num < min || num > max {
			return nil, fmt.Errorf("value %d out of range [%d, %d]", num, min, max)
		}
		if num != 0 { // Skip zero values for most BY* rules
			result = append(result, num)
		}
	}

	return result, nil
}

// generateRecurrenceInstances generates event instances based on the RRULE with improved logic
func (cs *CalendarService) generateRecurrenceInstances(event *models.CalendarEvent, rule *RRULERule) []models.CalendarEvent {
	var instances []models.CalendarEvent

	// Determine end condition with better defaults
	maxInstances := 1000 // Increased safety limit
	if rule.Count > 0 && rule.Count < maxInstances {
		maxInstances = rule.Count
	}

	// Default end time based on frequency
	var defaultEndTime time.Time
	switch rule.Frequency {
	case "DAILY":
		defaultEndTime = time.Now().AddDate(0, 6, 0) // 6 months for daily
	case "WEEKLY":
		defaultEndTime = time.Now().AddDate(1, 0, 0) // 1 year for weekly
	case "MONTHLY":
		defaultEndTime = time.Now().AddDate(2, 0, 0) // 2 years for monthly
	case "YEARLY":
		defaultEndTime = time.Now().AddDate(5, 0, 0) // 5 years for yearly
	default:
		defaultEndTime = time.Now().AddDate(1, 0, 0) // 1 year default
	}

	endTime := defaultEndTime
	if rule.Until != nil {
		endTime = *rule.Until
	}
	if event.RecurrenceUntil != nil && event.RecurrenceUntil.Before(endTime) {
		endTime = *event.RecurrenceUntil
	}

	duration := event.EndTime.Sub(event.StartTime)
	instanceCount := 0

	// Performance optimization: pre-calculate some values
	candidates := cs.generateCandidateTimes(event.StartTime, endTime, rule)

	for _, candidateTime := range candidates {
		if instanceCount >= maxInstances {
			break
		}

		// Check if this occurrence matches all rule criteria
		if cs.matchesAllRRULECriteria(candidateTime, rule, event.StartTime) {
			instance := *event
			instance.ID = "" // Clear ID for new instance
			instance.StartTime = candidateTime
			instance.EndTime = candidateTime.Add(duration)
			instance.ParentEventID = &event.ID

			instances = append(instances, instance)
			instanceCount++
		}
	}

	return instances
}

// generateCandidateTimes generates candidate times based on frequency and interval
func (cs *CalendarService) generateCandidateTimes(startTime, endTime time.Time, rule *RRULERule) []time.Time {
	var candidates []time.Time
	current := startTime

	for current.Before(endTime) && len(candidates) < 10000 { // Safety limit
		candidates = append(candidates, current)
		current = cs.getNextOccurrence(current, rule)
	}

	return candidates
}

// matchesAllRRULECriteria checks if a given time matches all RRULE criteria with comprehensive validation
func (cs *CalendarService) matchesAllRRULECriteria(t time.Time, rule *RRULERule, originalStart time.Time) bool {
	// Check BYDAY constraint
	if len(rule.ByDay) > 0 && !cs.matchesByDay(t, rule.ByDay, rule.Frequency) {
		return false
	}

	// Check BYMONTH constraint
	if len(rule.ByMonth) > 0 && !cs.matchesByMonth(t, rule.ByMonth) {
		return false
	}

	// Check BYMONTHDAY constraint
	if len(rule.ByMonthDay) > 0 && !cs.matchesByMonthDay(t, rule.ByMonthDay) {
		return false
	}

	// Check BYYEARDAY constraint
	if len(rule.ByYearDay) > 0 && !cs.matchesByYearDay(t, rule.ByYearDay) {
		return false
	}

	// Check BYWEEKNO constraint
	if len(rule.ByWeekNo) > 0 && !cs.matchesByWeekNo(t, rule.ByWeekNo, rule.WeekStart) {
		return false
	}

	// Check BYHOUR constraint
	if len(rule.ByHour) > 0 && !cs.matchesByHour(t, rule.ByHour) {
		return false
	}

	// Check BYMINUTE constraint
	if len(rule.ByMinute) > 0 && !cs.matchesByMinute(t, rule.ByMinute) {
		return false
	}

	// Check BYSECOND constraint
	if len(rule.BySecond) > 0 && !cs.matchesBySecond(t, rule.BySecond) {
		return false
	}

	return true
}

// Individual matching functions for better modularity
func (cs *CalendarService) matchesByDay(t time.Time, byDays []string, frequency string) bool {
	weekdayMap := map[string]time.Weekday{
		"SU": time.Sunday, "MO": time.Monday, "TU": time.Tuesday,
		"WE": time.Wednesday, "TH": time.Thursday, "FR": time.Friday, "SA": time.Saturday,
	}

	currentWeekday := t.Weekday()

	for _, byDay := range byDays {
		// Handle ordinal weekdays (e.g., 1MO, -1FR)
		if len(byDay) > 2 {
			ordinalStr := byDay[:len(byDay)-2]
			dayStr := byDay[len(byDay)-2:]

			ordinal, err := strconv.Atoi(ordinalStr)
			if err != nil {
				continue
			}

			if weekday, exists := weekdayMap[dayStr]; exists {
				if cs.matchesOrdinalWeekday(t, weekday, ordinal, frequency) {
					return true
				}
			}
		} else {
			// Simple weekday matching
			if weekday, exists := weekdayMap[byDay]; exists && weekday == currentWeekday {
				return true
			}
		}
	}

	return false
}

func (cs *CalendarService) matchesOrdinalWeekday(t time.Time, weekday time.Weekday, ordinal int, frequency string) bool {
	if frequency == "MONTHLY" {
		return cs.matchesMonthlyOrdinalWeekday(t, weekday, ordinal)
	} else if frequency == "YEARLY" {
		return cs.matchesYearlyOrdinalWeekday(t, weekday, ordinal)
	}
	return false
}

func (cs *CalendarService) matchesMonthlyOrdinalWeekday(t time.Time, weekday time.Weekday, ordinal int) bool {
	if t.Weekday() != weekday {
		return false
	}

	year, month, _ := t.Date()
	firstDay := time.Date(year, month, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	lastDay := firstDay.AddDate(0, 1, -1)

	if ordinal > 0 {
		// Positive ordinal: count from beginning of month
		count := 0
		for d := firstDay; d.Month() == month; d = d.AddDate(0, 0, 1) {
			if d.Weekday() == weekday {
				count++
				if count == ordinal && d.Day() == t.Day() {
					return true
				}
			}
		}
	} else {
		// Negative ordinal: count from end of month
		count := 0
		for d := lastDay; d.Month() == month; d = d.AddDate(0, 0, -1) {
			if d.Weekday() == weekday {
				count++
				if count == -ordinal && d.Day() == t.Day() {
					return true
				}
			}
		}
	}

	return false
}

func (cs *CalendarService) matchesYearlyOrdinalWeekday(t time.Time, weekday time.Weekday, ordinal int) bool {
	if t.Weekday() != weekday {
		return false
	}

	year := t.Year()
	firstDay := time.Date(year, 1, 1, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	lastDay := time.Date(year, 12, 31, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())

	if ordinal > 0 {
		// Positive ordinal: count from beginning of year
		count := 0
		for d := firstDay; d.Year() == year; d = d.AddDate(0, 0, 1) {
			if d.Weekday() == weekday {
				count++
				if count == ordinal && d.YearDay() == t.YearDay() {
					return true
				}
			}
		}
	} else {
		// Negative ordinal: count from end of year
		count := 0
		for d := lastDay; d.Year() == year; d = d.AddDate(0, 0, -1) {
			if d.Weekday() == weekday {
				count++
				if count == -ordinal && d.YearDay() == t.YearDay() {
					return true
				}
			}
		}
	}

	return false
}

func (cs *CalendarService) matchesByMonth(t time.Time, byMonths []int) bool {
	currentMonth := int(t.Month())
	for _, month := range byMonths {
		if month == currentMonth {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesByMonthDay(t time.Time, byMonthDays []int) bool {
	currentDay := t.Day()
	year, month, _ := t.Date()
	daysInMonth := time.Date(year, month+1, 0, 0, 0, 0, 0, t.Location()).Day()

	for _, day := range byMonthDays {
		if day > 0 && day == currentDay {
			return true
		} else if day < 0 && currentDay == daysInMonth+day+1 {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesByYearDay(t time.Time, byYearDays []int) bool {
	currentYearDay := t.YearDay()
	year := t.Year()
	daysInYear := 365
	if cs.isLeapYear(year) {
		daysInYear = 366
	}

	for _, day := range byYearDays {
		if day > 0 && day == currentYearDay {
			return true
		} else if day < 0 && currentYearDay == daysInYear+day+1 {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesByWeekNo(t time.Time, byWeekNos []int, weekStart string) bool {
	weekNo := cs.getWeekNumber(t, weekStart)
	for _, week := range byWeekNos {
		if week == weekNo {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesByHour(t time.Time, byHours []int) bool {
	currentHour := t.Hour()
	for _, hour := range byHours {
		if hour == currentHour {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesByMinute(t time.Time, byMinutes []int) bool {
	currentMinute := t.Minute()
	for _, minute := range byMinutes {
		if minute == currentMinute {
			return true
		}
	}
	return false
}

func (cs *CalendarService) matchesBySecond(t time.Time, bySeconds []int) bool {
	currentSecond := t.Second()
	for _, second := range bySeconds {
		if second == currentSecond {
			return true
		}
	}
	return false
}

// Helper functions
func (cs *CalendarService) isLeapYear(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

func (cs *CalendarService) getWeekNumber(t time.Time, weekStart string) int {
	// This is a simplified week number calculation
	// For production, consider using a proper ISO week calculation
	_, week := t.ISOWeek()
	return week
}

// getNextOccurrence calculates the next potential occurrence based on frequency and interval
func (cs *CalendarService) getNextOccurrence(current time.Time, rule *RRULERule) time.Time {
	switch rule.Frequency {
	case "DAILY":
		return current.AddDate(0, 0, rule.Interval)
	case "WEEKLY":
		return current.AddDate(0, 0, 7*rule.Interval)
	case "MONTHLY":
		return current.AddDate(0, rule.Interval, 0)
	case "YEARLY":
		return current.AddDate(rule.Interval, 0, 0)
	default:
		// Default to daily if frequency is unknown
		return current.AddDate(0, 0, 1)
	}
}
