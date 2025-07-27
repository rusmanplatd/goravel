package services

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"github.com/oschwald/geoip2-golang"
)

// GeoIPService provides geolocation services using MaxMind GeoIP2
type GeoIPService struct {
	cityDB    *geoip2.Reader
	asnDB     *geoip2.Reader
	mu        sync.RWMutex
	isEnabled bool
}

// NewGeoIPService creates a new GeoIP service instance
func NewGeoIPService() *GeoIPService {
	service := &GeoIPService{
		isEnabled: false,
	}

	// Initialize databases
	if err := service.initializeDatabases(); err != nil {
		facades.Log().Warning("GeoIP service initialization failed", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return service
}

// initializeDatabases initializes the MaxMind databases
func (g *GeoIPService) initializeDatabases() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Get database paths from config
	cityDBPath := facades.Config().GetString("geoip.city_db_path", "storage/geoip/GeoLite2-City.mmdb")
	asnDBPath := facades.Config().GetString("geoip.asn_db_path", "storage/geoip/GeoLite2-ASN.mmdb")

	// Try to open city database
	if cityDB, err := geoip2.Open(cityDBPath); err == nil {
		g.cityDB = cityDB
		facades.Log().Info("GeoIP City database loaded successfully", map[string]interface{}{
			"path": cityDBPath,
		})
	} else {
		facades.Log().Warning("Failed to load GeoIP City database", map[string]interface{}{
			"path":  cityDBPath,
			"error": err.Error(),
		})
	}

	// Try to open ASN database
	if asnDB, err := geoip2.Open(asnDBPath); err == nil {
		g.asnDB = asnDB
		facades.Log().Info("GeoIP ASN database loaded successfully", map[string]interface{}{
			"path": asnDBPath,
		})
	} else {
		facades.Log().Warning("Failed to load GeoIP ASN database", map[string]interface{}{
			"path":  asnDBPath,
			"error": err.Error(),
		})
	}

	// Service is enabled if at least one database is available
	g.isEnabled = g.cityDB != nil || g.asnDB != nil

	return nil
}

// GetLocation returns geolocation information for an IP address
func (g *GeoIPService) GetLocation(ipAddress string) *models.GeoLocation {
	// Handle localhost and private IPs
	if g.isLocalOrPrivateIP(ipAddress) {
		return &models.GeoLocation{
			Country:     "Local",
			CountryCode: "LO",
			Region:      "Local",
			RegionCode:  "LO",
			City:        "Local",
			ISP:         "Local Network",
			IsProxy:     false,
			IsVPN:       false,
			IsTor:       false,
		}
	}

	// Parse IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return g.getUnknownLocation()
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if !g.isEnabled {
		return g.getUnknownLocation()
	}

	location := &models.GeoLocation{}

	// Get city information
	if g.cityDB != nil {
		if cityRecord, err := g.cityDB.City(ip); err == nil {
			location.Country = cityRecord.Country.Names["en"]
			location.CountryCode = cityRecord.Country.IsoCode
			location.City = cityRecord.City.Names["en"]
			location.PostalCode = cityRecord.Postal.Code
			location.TimeZone = cityRecord.Location.TimeZone
			location.Latitude = cityRecord.Location.Latitude
			location.Longitude = cityRecord.Location.Longitude

			// Get region information
			if len(cityRecord.Subdivisions) > 0 {
				location.Region = cityRecord.Subdivisions[0].Names["en"]
				location.RegionCode = cityRecord.Subdivisions[0].IsoCode
			}

			// Check for proxy/VPN/Tor indicators
			location.IsProxy = cityRecord.Traits.IsAnonymousProxy
			location.IsVPN = cityRecord.Traits.IsAnonymousProxy || cityRecord.Traits.IsSatelliteProvider
			// Tor detection would require additional data sources
		}
	}

	// Get ASN information
	if g.asnDB != nil {
		if asnRecord, err := g.asnDB.ASN(ip); err == nil {
			location.ASN = asnRecord.AutonomousSystemNumber
			location.ASNOrg = asnRecord.AutonomousSystemOrganization
			location.ISP = asnRecord.AutonomousSystemOrganization

			// Enhanced VPN/Proxy detection based on ASN
			location.IsVPN = location.IsVPN || g.isKnownVPNProvider(asnRecord.AutonomousSystemOrganization)
		}
	}

	// Set defaults for empty fields
	if location.Country == "" {
		location.Country = "Unknown"
	}
	if location.Region == "" {
		location.Region = "Unknown"
	}
	if location.City == "" {
		location.City = "Unknown"
	}
	if location.ISP == "" {
		location.ISP = "Unknown"
	}

	return location
}

// GetCountryCode returns just the country code for an IP address
func (g *GeoIPService) GetCountryCode(ipAddress string) string {
	location := g.GetLocation(ipAddress)
	return location.CountryCode
}

// GetCity returns just the city for an IP address
func (g *GeoIPService) GetCity(ipAddress string) string {
	location := g.GetLocation(ipAddress)
	return location.City
}

// IsVPN checks if an IP address is likely from a VPN
func (g *GeoIPService) IsVPN(ipAddress string) bool {
	location := g.GetLocation(ipAddress)
	return location.IsVPN
}

// IsProxy checks if an IP address is from a proxy
func (g *GeoIPService) IsProxy(ipAddress string) bool {
	location := g.GetLocation(ipAddress)
	return location.IsProxy
}

// IsTor checks if an IP address is from Tor (requires additional data)
func (g *GeoIPService) IsTor(ipAddress string) bool {
	location := g.GetLocation(ipAddress)
	return location.IsTor
}

// Close closes the GeoIP databases
func (g *GeoIPService) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var errors []error

	if g.cityDB != nil {
		if err := g.cityDB.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close city DB: %w", err))
		}
		g.cityDB = nil
	}

	if g.asnDB != nil {
		if err := g.asnDB.Close(); err != nil {
			errors = append(errors, fmt.Errorf("failed to close ASN DB: %w", err))
		}
		g.asnDB = nil
	}

	g.isEnabled = false

	if len(errors) > 0 {
		return fmt.Errorf("errors closing GeoIP service: %v", errors)
	}

	return nil
}

// IsEnabled returns whether the GeoIP service is enabled
func (g *GeoIPService) IsEnabled() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.isEnabled
}

// Helper methods

func (g *GeoIPService) isLocalOrPrivateIP(ipAddress string) bool {
	if ipAddress == "" || ipAddress == "127.0.0.1" || ipAddress == "::1" {
		return true
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 unique local addresses
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (g *GeoIPService) getUnknownLocation() *models.GeoLocation {
	return &models.GeoLocation{
		Country:     "Unknown",
		CountryCode: "XX",
		Region:      "Unknown",
		RegionCode:  "XX",
		City:        "Unknown",
		ISP:         "Unknown",
		IsProxy:     false,
		IsVPN:       false,
		IsTor:       false,
	}
}

func (g *GeoIPService) isKnownVPNProvider(org string) bool {
	// List of known VPN/proxy providers (simplified)
	vpnProviders := []string{
		"ExpressVPN",
		"NordVPN",
		"Surfshark",
		"CyberGhost",
		"Private Internet Access",
		"ProtonVPN",
		"Windscribe",
		"TunnelBear",
		"VyprVPN",
		"IPVanish",
		"Cloudflare",
		"DigitalOcean",
		"Amazon",
		"Google",
		"Microsoft",
		"Linode",
		"Vultr",
	}

	orgLower := strings.ToLower(org)
	for _, provider := range vpnProviders {
		if strings.Contains(orgLower, strings.ToLower(provider)) {
			return true
		}
	}

	return false
}

// UpdateDatabases updates the GeoIP databases (for scheduled updates)
func (g *GeoIPService) UpdateDatabases() error {
	// Close existing databases
	if err := g.Close(); err != nil {
		facades.Log().Warning("Failed to close existing databases during update", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Reinitialize with new databases
	return g.initializeDatabases()
}

// GetDatabaseInfo returns information about loaded databases
func (g *GeoIPService) GetDatabaseInfo() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()

	info := map[string]interface{}{
		"enabled":   g.isEnabled,
		"city_db":   g.cityDB != nil,
		"asn_db":    g.asnDB != nil,
		"databases": []string{},
	}

	if g.cityDB != nil {
		info["databases"] = append(info["databases"].([]string), "City")
	}
	if g.asnDB != nil {
		info["databases"] = append(info["databases"].([]string), "ASN")
	}

	return info
}
