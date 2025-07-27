package services

import (
	"regexp"
	"strings"
)

// UserAgentParser provides comprehensive user agent parsing
type UserAgentParser struct {
	browserRegexes []BrowserRegex
	osRegexes      []OSRegex
	deviceRegexes  []DeviceRegex
}

// BrowserRegex defines browser detection patterns
type BrowserRegex struct {
	Pattern string
	Name    string
	Version string
}

// OSRegex defines operating system detection patterns
type OSRegex struct {
	Pattern string
	Name    string
	Version string
}

// DeviceRegex defines device type detection patterns
type DeviceRegex struct {
	Pattern    string
	DeviceType string
	Brand      string
	Model      string
}

// ParsedUserAgent contains parsed user agent information
type ParsedUserAgent struct {
	UserAgent string                 `json:"user_agent"`
	Browser   BrowserInfo            `json:"browser"`
	OS        OSInfo                 `json:"os"`
	Device    DeviceInfo             `json:"device"`
	IsBot     bool                   `json:"is_bot"`
	IsMobile  bool                   `json:"is_mobile"`
	IsTablet  bool                   `json:"is_tablet"`
	IsDesktop bool                   `json:"is_desktop"`
	Raw       map[string]interface{} `json:"raw"`
}

// BrowserInfo contains browser information
type BrowserInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Major   string `json:"major"`
}

// OSInfo contains operating system information
type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Family  string `json:"family"`
}

// DeviceInfo contains device information
type DeviceInfo struct {
	Type   string `json:"type"`   // mobile, tablet, desktop, tv, console, etc.
	Brand  string `json:"brand"`  // Apple, Samsung, Google, etc.
	Model  string `json:"model"`  // iPhone, Galaxy S21, etc.
	Family string `json:"family"` // iPhone, Galaxy, etc.
}

// NewUserAgentParser creates a new user agent parser with predefined patterns
func NewUserAgentParser() *UserAgentParser {
	return &UserAgentParser{
		browserRegexes: getBrowserRegexes(),
		osRegexes:      getOSRegexes(),
		deviceRegexes:  getDeviceRegexes(),
	}
}

// Parse parses a user agent string and returns detailed information
func (p *UserAgentParser) Parse(userAgent string) *ParsedUserAgent {
	if userAgent == "" {
		return p.getDefaultParsedUserAgent("")
	}

	parsed := &ParsedUserAgent{
		UserAgent: userAgent,
		Browser:   p.parseBrowser(userAgent),
		OS:        p.parseOS(userAgent),
		Device:    p.parseDevice(userAgent),
		IsBot:     p.isBot(userAgent),
		Raw:       make(map[string]interface{}),
	}

	// Determine device categories
	parsed.IsMobile = p.isMobile(userAgent, parsed.Device.Type)
	parsed.IsTablet = p.isTablet(userAgent, parsed.Device.Type)
	parsed.IsDesktop = p.isDesktop(userAgent, parsed.Device.Type, parsed.IsMobile, parsed.IsTablet)

	// Store additional raw information
	parsed.Raw["length"] = len(userAgent)
	parsed.Raw["contains_mobile"] = strings.Contains(strings.ToLower(userAgent), "mobile")
	parsed.Raw["contains_tablet"] = strings.Contains(strings.ToLower(userAgent), "tablet")

	return parsed
}

// parseBrowser extracts browser information from user agent
func (p *UserAgentParser) parseBrowser(userAgent string) BrowserInfo {
	browser := BrowserInfo{
		Name:    "Unknown",
		Version: "Unknown",
		Major:   "Unknown",
	}

	for _, regex := range p.browserRegexes {
		re := regexp.MustCompile(regex.Pattern)
		matches := re.FindStringSubmatch(userAgent)

		if len(matches) > 0 {
			browser.Name = regex.Name

			// Extract version if pattern includes version group
			if len(matches) > 1 && matches[1] != "" {
				browser.Version = matches[1]
				// Extract major version (first number)
				if versionParts := strings.Split(matches[1], "."); len(versionParts) > 0 {
					browser.Major = versionParts[0]
				}
			}
			break
		}
	}

	return browser
}

// parseOS extracts operating system information from user agent
func (p *UserAgentParser) parseOS(userAgent string) OSInfo {
	os := OSInfo{
		Name:    "Unknown",
		Version: "Unknown",
		Family:  "Unknown",
	}

	for _, regex := range p.osRegexes {
		re := regexp.MustCompile(regex.Pattern)
		matches := re.FindStringSubmatch(userAgent)

		if len(matches) > 0 {
			os.Name = regex.Name

			// Extract version if pattern includes version group
			if len(matches) > 1 && matches[1] != "" {
				os.Version = matches[1]
			}

			// Set OS family
			os.Family = p.getOSFamily(os.Name)
			break
		}
	}

	return os
}

// parseDevice extracts device information from user agent
func (p *UserAgentParser) parseDevice(userAgent string) DeviceInfo {
	device := DeviceInfo{
		Type:   "desktop", // default
		Brand:  "Unknown",
		Model:  "Unknown",
		Family: "Unknown",
	}

	for _, regex := range p.deviceRegexes {
		re := regexp.MustCompile(regex.Pattern)
		matches := re.FindStringSubmatch(userAgent)

		if len(matches) > 0 {
			device.Type = regex.DeviceType
			device.Brand = regex.Brand

			// Extract model if pattern includes model group
			if len(matches) > 1 && matches[1] != "" {
				device.Model = matches[1]
			}

			device.Family = p.getDeviceFamily(device.Brand, device.Model)
			break
		}
	}

	return device
}

// isBot checks if the user agent represents a bot/crawler
func (p *UserAgentParser) isBot(userAgent string) bool {
	botPatterns := []string{
		`(?i)(bot|crawler|spider|scraper)`,
		`(?i)(googlebot|bingbot|slurp|duckduckbot)`,
		`(?i)(facebookexternalhit|twitterbot|linkedinbot)`,
		`(?i)(whatsapp|telegram|discord)`,
		`(?i)(curl|wget|python-requests|go-http-client)`,
		`(?i)(headless|phantom|selenium)`,
	}

	for _, pattern := range botPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return true
		}
	}

	return false
}

// isMobile determines if the device is mobile
func (p *UserAgentParser) isMobile(userAgent, deviceType string) bool {
	if deviceType == "mobile" {
		return true
	}

	mobilePatterns := []string{
		`(?i)(mobile|android|iphone|ipod|blackberry|webos|opera mini)`,
		`(?i)(windows phone|windows ce|symbian|palm)`,
	}

	for _, pattern := range mobilePatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return true
		}
	}

	return false
}

// isTablet determines if the device is a tablet
func (p *UserAgentParser) isTablet(userAgent, deviceType string) bool {
	if deviceType == "tablet" {
		return true
	}

	tabletPatterns := []string{
		`(?i)(ipad|tablet|kindle|nook|playbook)`,
		`(?i)(android(?!.*mobile))`, // Android without mobile keyword
	}

	for _, pattern := range tabletPatterns {
		if matched, _ := regexp.MatchString(pattern, userAgent); matched {
			return true
		}
	}

	return false
}

// isDesktop determines if the device is desktop
func (p *UserAgentParser) isDesktop(userAgent, deviceType string, isMobile, isTablet bool) bool {
	if deviceType == "desktop" || (!isMobile && !isTablet) {
		return true
	}

	return false
}

// getOSFamily returns the OS family for a given OS name
func (p *UserAgentParser) getOSFamily(osName string) string {
	families := map[string]string{
		"Windows":   "Windows",
		"macOS":     "macOS",
		"iOS":       "iOS",
		"Android":   "Android",
		"Linux":     "Linux",
		"Ubuntu":    "Linux",
		"Chrome OS": "Chrome OS",
		"FreeBSD":   "BSD",
		"OpenBSD":   "BSD",
		"NetBSD":    "BSD",
	}

	if family, exists := families[osName]; exists {
		return family
	}

	return "Other"
}

// getDeviceFamily returns the device family
func (p *UserAgentParser) getDeviceFamily(brand, model string) string {
	if brand == "Apple" {
		if strings.Contains(model, "iPhone") {
			return "iPhone"
		} else if strings.Contains(model, "iPad") {
			return "iPad"
		} else if strings.Contains(model, "Mac") {
			return "Mac"
		}
	} else if brand == "Samsung" {
		if strings.Contains(model, "Galaxy") {
			return "Galaxy"
		}
	} else if brand == "Google" {
		if strings.Contains(model, "Pixel") {
			return "Pixel"
		}
	}

	return model
}

// getDefaultParsedUserAgent returns a default parsed user agent
func (p *UserAgentParser) getDefaultParsedUserAgent(userAgent string) *ParsedUserAgent {
	return &ParsedUserAgent{
		UserAgent: userAgent,
		Browser: BrowserInfo{
			Name:    "Unknown",
			Version: "Unknown",
			Major:   "Unknown",
		},
		OS: OSInfo{
			Name:    "Unknown",
			Version: "Unknown",
			Family:  "Unknown",
		},
		Device: DeviceInfo{
			Type:   "unknown",
			Brand:  "Unknown",
			Model:  "Unknown",
			Family: "Unknown",
		},
		IsBot:     false,
		IsMobile:  false,
		IsTablet:  false,
		IsDesktop: false,
		Raw:       make(map[string]interface{}),
	}
}

// getBrowserRegexes returns predefined browser detection patterns
func getBrowserRegexes() []BrowserRegex {
	return []BrowserRegex{
		// Chrome must come before Safari since Chrome includes Safari in UA
		{Pattern: `Chrome/([0-9\.]+)`, Name: "Chrome"},
		{Pattern: `Chromium/([0-9\.]+)`, Name: "Chromium"},
		{Pattern: `Firefox/([0-9\.]+)`, Name: "Firefox"},
		{Pattern: `Safari/[0-9\.]+ Version/([0-9\.]+)`, Name: "Safari"},
		{Pattern: `Edge/([0-9\.]+)`, Name: "Edge"},
		{Pattern: `Edg/([0-9\.]+)`, Name: "Edge"}, // New Edge
		{Pattern: `Opera/([0-9\.]+)`, Name: "Opera"},
		{Pattern: `OPR/([0-9\.]+)`, Name: "Opera"}, // Opera 15+
		{Pattern: `MSIE ([0-9\.]+)`, Name: "Internet Explorer"},
		{Pattern: `Trident/.*rv:([0-9\.]+)`, Name: "Internet Explorer"}, // IE 11
		{Pattern: `YaBrowser/([0-9\.]+)`, Name: "Yandex Browser"},
		{Pattern: `UCBrowser/([0-9\.]+)`, Name: "UC Browser"},
		{Pattern: `SamsungBrowser/([0-9\.]+)`, Name: "Samsung Internet"},
		{Pattern: `Vivaldi/([0-9\.]+)`, Name: "Vivaldi"},
		{Pattern: `Brave/([0-9\.]+)`, Name: "Brave"},
	}
}

// getOSRegexes returns predefined OS detection patterns
func getOSRegexes() []OSRegex {
	return []OSRegex{
		// Windows
		{Pattern: `Windows NT 10\.0`, Name: "Windows 10"},
		{Pattern: `Windows NT 6\.3`, Name: "Windows 8.1"},
		{Pattern: `Windows NT 6\.2`, Name: "Windows 8"},
		{Pattern: `Windows NT 6\.1`, Name: "Windows 7"},
		{Pattern: `Windows NT 6\.0`, Name: "Windows Vista"},
		{Pattern: `Windows NT 5\.1`, Name: "Windows XP"},
		{Pattern: `Windows NT ([0-9\.]+)`, Name: "Windows"},

		// macOS/Mac OS X
		{Pattern: `Mac OS X 10[._]([0-9_\.]+)`, Name: "macOS"},
		{Pattern: `Mac OS X`, Name: "macOS"},
		{Pattern: `Macintosh`, Name: "macOS"},

		// iOS
		{Pattern: `iPhone OS ([0-9_\.]+)`, Name: "iOS"},
		{Pattern: `OS ([0-9_\.]+) like Mac OS X`, Name: "iOS"},

		// Android
		{Pattern: `Android ([0-9\.]+)`, Name: "Android"},
		{Pattern: `Android`, Name: "Android"},

		// Linux distributions
		{Pattern: `Ubuntu/([0-9\.]+)`, Name: "Ubuntu"},
		{Pattern: `Ubuntu`, Name: "Ubuntu"},
		{Pattern: `Linux`, Name: "Linux"},

		// Chrome OS
		{Pattern: `CrOS`, Name: "Chrome OS"},

		// BSD variants
		{Pattern: `FreeBSD`, Name: "FreeBSD"},
		{Pattern: `OpenBSD`, Name: "OpenBSD"},
		{Pattern: `NetBSD`, Name: "NetBSD"},
	}
}

// getDeviceRegexes returns predefined device detection patterns
func getDeviceRegexes() []DeviceRegex {
	return []DeviceRegex{
		// Mobile devices
		{Pattern: `iPhone`, DeviceType: "mobile", Brand: "Apple", Model: "iPhone"},
		{Pattern: `iPod`, DeviceType: "mobile", Brand: "Apple", Model: "iPod"},
		{Pattern: `Android.*Mobile`, DeviceType: "mobile", Brand: "Android", Model: "Android Phone"},
		{Pattern: `BlackBerry`, DeviceType: "mobile", Brand: "BlackBerry", Model: "BlackBerry"},
		{Pattern: `Windows Phone`, DeviceType: "mobile", Brand: "Microsoft", Model: "Windows Phone"},

		// Tablets
		{Pattern: `iPad`, DeviceType: "tablet", Brand: "Apple", Model: "iPad"},
		{Pattern: `Android(?!.*Mobile)`, DeviceType: "tablet", Brand: "Android", Model: "Android Tablet"},
		{Pattern: `Kindle`, DeviceType: "tablet", Brand: "Amazon", Model: "Kindle"},

		// Gaming consoles
		{Pattern: `PlayStation`, DeviceType: "console", Brand: "Sony", Model: "PlayStation"},
		{Pattern: `Xbox`, DeviceType: "console", Brand: "Microsoft", Model: "Xbox"},
		{Pattern: `Nintendo`, DeviceType: "console", Brand: "Nintendo", Model: "Nintendo"},

		// Smart TVs
		{Pattern: `Smart-TV`, DeviceType: "tv", Brand: "Smart TV", Model: "Smart TV"},
		{Pattern: `AppleTV`, DeviceType: "tv", Brand: "Apple", Model: "Apple TV"},

		// Default desktop
		{Pattern: `.*`, DeviceType: "desktop", Brand: "Unknown", Model: "Desktop"},
	}
}

// ParseUserAgent is a convenience function to parse user agent with default parser
func ParseUserAgent(userAgent string) *ParsedUserAgent {
	parser := NewUserAgentParser()
	return parser.Parse(userAgent)
}

// GetDeviceFingerprint creates a device fingerprint from parsed user agent
func (p *ParsedUserAgent) GetDeviceFingerprint() string {
	return strings.Join([]string{
		p.Browser.Name,
		p.Browser.Major,
		p.OS.Name,
		p.Device.Type,
		p.Device.Brand,
	}, "|")
}

// IsSecure determines if the user agent represents a secure/trusted client
func (p *ParsedUserAgent) IsSecure() bool {
	// Bots and unknown browsers are less secure
	if p.IsBot || p.Browser.Name == "Unknown" {
		return false
	}

	// Very old browsers are less secure
	insecureBrowsers := map[string][]string{
		"Internet Explorer": {"6", "7", "8", "9", "10"},
		"Chrome":            {"1", "2", "3", "4", "5"},
		"Firefox":           {"1", "2", "3"},
		"Safari":            {"1", "2", "3", "4"},
	}

	if versions, exists := insecureBrowsers[p.Browser.Name]; exists {
		for _, version := range versions {
			if p.Browser.Major == version {
				return false
			}
		}
	}

	return true
}

// GetRiskScore calculates a risk score based on user agent characteristics
func (p *ParsedUserAgent) GetRiskScore() int {
	score := 0

	// Bot detection adds risk
	if p.IsBot {
		score += 30
	}

	// Unknown browser/OS adds risk
	if p.Browser.Name == "Unknown" {
		score += 20
	}
	if p.OS.Name == "Unknown" {
		score += 15
	}

	// Very short or very long user agents are suspicious
	uaLength := len(p.UserAgent)
	if uaLength < 50 || uaLength > 1000 {
		score += 10
	}

	// Insecure clients add risk
	if !p.IsSecure() {
		score += 25
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}
