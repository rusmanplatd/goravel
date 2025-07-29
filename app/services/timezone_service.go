package services

import (
	"fmt"
	"strings"
	"time"
)

type TimezoneService struct{}

func NewTimezoneService() *TimezoneService {
	return &TimezoneService{}
}

// Common timezone mappings
var timezoneMap = map[string]string{
	// US Timezones
	"EST":  "America/New_York",
	"EDT":  "America/New_York",
	"CST":  "America/Chicago",
	"CDT":  "America/Chicago",
	"MST":  "America/Denver",
	"MDT":  "America/Denver",
	"PST":  "America/Los_Angeles",
	"PDT":  "America/Los_Angeles",
	"AKST": "America/Anchorage",
	"AKDT": "America/Anchorage",
	"HST":  "Pacific/Honolulu",
	"HDT":  "Pacific/Honolulu",

	// European Timezones
	"GMT":  "Europe/London",
	"BST":  "Europe/London",
	"CET":  "Europe/Paris",
	"CEST": "Europe/Paris",
	"EET":  "Europe/Athens",
	"EEST": "Europe/Athens",

	// Asian Timezones
	"JST": "Asia/Tokyo",
	"KST": "Asia/Seoul",
	"CCT": "Asia/Shanghai", // China Coast Time
	"IST": "Asia/Kolkata",
	"SGT": "Asia/Singapore",

	// Australian Timezones
	"AEST": "Australia/Sydney",
	"AEDT": "Australia/Sydney",
	"ACST": "Australia/Adelaide",
	"ACDT": "Australia/Adelaide",
	"AWST": "Australia/Perth",
}

// Popular timezone choices for UI
var popularTimezones = []map[string]string{
	{"name": "Pacific Time (US & Canada)", "value": "America/Los_Angeles"},
	{"name": "Mountain Time (US & Canada)", "value": "America/Denver"},
	{"name": "Central Time (US & Canada)", "value": "America/Chicago"},
	{"name": "Eastern Time (US & Canada)", "value": "America/New_York"},
	{"name": "Greenwich Mean Time", "value": "Europe/London"},
	{"name": "Central European Time", "value": "Europe/Paris"},
	{"name": "Eastern European Time", "value": "Europe/Athens"},
	{"name": "Japan Standard Time", "value": "Asia/Tokyo"},
	{"name": "China Standard Time", "value": "Asia/Shanghai"},
	{"name": "India Standard Time", "value": "Asia/Kolkata"},
	{"name": "Australian Eastern Time", "value": "Australia/Sydney"},
	{"name": "UTC", "value": "UTC"},
}

// DetectTimezoneFromBrowser attempts to detect timezone from browser info
func (ts *TimezoneService) DetectTimezoneFromBrowser(browserTimezone string) string {
	if browserTimezone == "" {
		return "UTC"
	}

	// If it's already a valid IANA timezone, return it
	if _, err := time.LoadLocation(browserTimezone); err == nil {
		return browserTimezone
	}

	// Try to map common abbreviations
	if mapped, exists := timezoneMap[strings.ToUpper(browserTimezone)]; exists {
		return mapped
	}

	// Default to UTC if we can't determine
	return "UTC"
}

// ConvertTime converts a time from one timezone to another
func (ts *TimezoneService) ConvertTime(t time.Time, fromTZ, toTZ string) (time.Time, error) {
	// Load source timezone
	fromLoc, err := time.LoadLocation(fromTZ)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid source timezone %s: %v", fromTZ, err)
	}

	// Load destination timezone
	toLoc, err := time.LoadLocation(toTZ)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid destination timezone %s: %v", toTZ, err)
	}

	// Convert time to source timezone first (if it's not already)
	if t.Location().String() != fromTZ {
		t = t.In(fromLoc)
	}

	// Convert to destination timezone
	return t.In(toLoc), nil
}

// GetTimezoneOffset returns the offset in minutes for a timezone at a specific time
func (ts *TimezoneService) GetTimezoneOffset(timezone string, t time.Time) (int, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return 0, fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	_, offset := t.In(loc).Zone()
	return offset / 60, nil // Convert seconds to minutes
}

// GetTimezoneAbbreviation returns the timezone abbreviation for a specific time
func (ts *TimezoneService) GetTimezoneAbbreviation(timezone string, t time.Time) (string, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	abbr, _ := t.In(loc).Zone()
	return abbr, nil
}

// FormatTimeInTimezone formats a time in a specific timezone
func (ts *TimezoneService) FormatTimeInTimezone(t time.Time, timezone, format string) (string, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return "", fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	return t.In(loc).Format(format), nil
}

// GetUserFriendlyTimezone returns a user-friendly timezone name
func (ts *TimezoneService) GetUserFriendlyTimezone(timezone string) string {
	for _, tz := range popularTimezones {
		if tz["value"] == timezone {
			return tz["name"]
		}
	}

	// If not found in popular list, return the timezone as-is but cleaned up
	parts := strings.Split(timezone, "/")
	if len(parts) >= 2 {
		city := strings.ReplaceAll(parts[len(parts)-1], "_", " ")
		return city + " Time"
	}

	return timezone
}

// GetPopularTimezones returns a list of popular timezones for UI
func (ts *TimezoneService) GetPopularTimezones() []map[string]string {
	return popularTimezones
}

// ValidateTimezone checks if a timezone is valid
func (ts *TimezoneService) ValidateTimezone(timezone string) bool {
	_, err := time.LoadLocation(timezone)
	return err == nil
}

// GetTimezoneChoices returns timezone choices grouped by region
func (ts *TimezoneService) GetTimezoneChoices() map[string][]map[string]string {
	return map[string][]map[string]string{
		"Popular": popularTimezones,
		"Americas": {
			{"name": "New York", "value": "America/New_York"},
			{"name": "Chicago", "value": "America/Chicago"},
			{"name": "Denver", "value": "America/Denver"},
			{"name": "Los Angeles", "value": "America/Los_Angeles"},
			{"name": "Toronto", "value": "America/Toronto"},
			{"name": "Vancouver", "value": "America/Vancouver"},
			{"name": "Mexico City", "value": "America/Mexico_City"},
			{"name": "São Paulo", "value": "America/Sao_Paulo"},
			{"name": "Buenos Aires", "value": "America/Argentina/Buenos_Aires"},
		},
		"Europe": {
			{"name": "London", "value": "Europe/London"},
			{"name": "Paris", "value": "Europe/Paris"},
			{"name": "Berlin", "value": "Europe/Berlin"},
			{"name": "Rome", "value": "Europe/Rome"},
			{"name": "Madrid", "value": "Europe/Madrid"},
			{"name": "Amsterdam", "value": "Europe/Amsterdam"},
			{"name": "Stockholm", "value": "Europe/Stockholm"},
			{"name": "Moscow", "value": "Europe/Moscow"},
		},
		"Asia": {
			{"name": "Tokyo", "value": "Asia/Tokyo"},
			{"name": "Shanghai", "value": "Asia/Shanghai"},
			{"name": "Hong Kong", "value": "Asia/Hong_Kong"},
			{"name": "Singapore", "value": "Asia/Singapore"},
			{"name": "Mumbai", "value": "Asia/Kolkata"},
			{"name": "Dubai", "value": "Asia/Dubai"},
			{"name": "Seoul", "value": "Asia/Seoul"},
			{"name": "Bangkok", "value": "Asia/Bangkok"},
		},
		"Australia": {
			{"name": "Sydney", "value": "Australia/Sydney"},
			{"name": "Melbourne", "value": "Australia/Melbourne"},
			{"name": "Brisbane", "value": "Australia/Brisbane"},
			{"name": "Perth", "value": "Australia/Perth"},
			{"name": "Adelaide", "value": "Australia/Adelaide"},
		},
		"Other": {
			{"name": "UTC", "value": "UTC"},
			{"name": "GMT", "value": "GMT"},
		},
	}
}

// ParseTimeWithTimezone parses a time string with timezone information
func (ts *TimezoneService) ParseTimeWithTimezone(timeStr, timezone string) (time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	// Try different time formats
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04",
		"2006-01-02",
		time.RFC3339,
		time.RFC3339Nano,
	}

	for _, format := range formats {
		if t, err := time.ParseInLocation(format, timeStr, loc); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time string: %s", timeStr)
}

// GetCurrentTimeInTimezone returns the current time in a specific timezone
func (ts *TimezoneService) GetCurrentTimeInTimezone(timezone string) (time.Time, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	return time.Now().In(loc), nil
}

// IsDaylightSavingTime checks if a timezone is currently observing daylight saving time
func (ts *TimezoneService) IsDaylightSavingTime(timezone string, t time.Time) (bool, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return false, fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	// Get the timezone abbreviation and offset
	abbr, offset := t.In(loc).Zone()

	// Check if this is likely DST by comparing with standard time
	// This is a heuristic approach - DST typically has different abbreviations
	standardTime := time.Date(t.Year(), 1, 15, 12, 0, 0, 0, loc) // Mid-January
	stdAbbr, stdOffset := standardTime.Zone()

	// If abbreviation or offset differs from standard time, likely DST
	return abbr != stdAbbr || offset != stdOffset, nil
}

// ConvertEventTimesToUserTimezone converts event times to user's timezone
func (ts *TimezoneService) ConvertEventTimesToUserTimezone(events []map[string]interface{}, userTimezone string) ([]map[string]interface{}, error) {
	userLoc, err := time.LoadLocation(userTimezone)
	if err != nil {
		return events, fmt.Errorf("invalid user timezone %s: %v", userTimezone, err)
	}

	for i, event := range events {
		// Convert start_time
		if startTimeStr, ok := event["start_time"].(string); ok {
			if startTime, err := time.Parse(time.RFC3339, startTimeStr); err == nil {
				events[i]["start_time"] = startTime.In(userLoc).Format(time.RFC3339)
				events[i]["start_time_local"] = startTime.In(userLoc).Format("2006-01-02 15:04:05")
			}
		}

		// Convert end_time
		if endTimeStr, ok := event["end_time"].(string); ok {
			if endTime, err := time.Parse(time.RFC3339, endTimeStr); err == nil {
				events[i]["end_time"] = endTime.In(userLoc).Format(time.RFC3339)
				events[i]["end_time_local"] = endTime.In(userLoc).Format("2006-01-02 15:04:05")
			}
		}
	}

	return events, nil
}

// GetTimezoneInfo returns comprehensive timezone information
func (ts *TimezoneService) GetTimezoneInfo(timezone string) (map[string]interface{}, error) {
	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, fmt.Errorf("invalid timezone %s: %v", timezone, err)
	}

	now := time.Now().In(loc)
	abbr, offset := now.Zone()

	isDST, _ := ts.IsDaylightSavingTime(timezone, now)

	return map[string]interface{}{
		"timezone":               timezone,
		"friendly_name":          ts.GetUserFriendlyTimezone(timezone),
		"abbreviation":           abbr,
		"offset_minutes":         offset / 60,
		"offset_hours":           float64(offset) / 3600,
		"is_dst":                 isDST,
		"current_time":           now.Format(time.RFC3339),
		"current_time_formatted": now.Format("Monday, January 2, 2006 at 3:04 PM"),
	}, nil
}
