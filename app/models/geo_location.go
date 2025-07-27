package models

// GeoLocation represents geographical information
// @Description Geographical location data for IP addresses
type GeoLocation struct {
	// Country name
	// @example United States
	Country string `json:"country,omitempty" example:"United States"`

	// ISO country code
	// @example US
	CountryCode string `json:"country_code,omitempty" example:"US"`

	// Region/state name
	// @example California
	Region string `json:"region,omitempty" example:"California"`

	// Region/state code
	// @example CA
	RegionCode string `json:"region_code,omitempty" example:"CA"`

	// City name
	// @example San Francisco
	City string `json:"city,omitempty" example:"San Francisco"`

	// Postal/ZIP code
	// @example 94102
	PostalCode string `json:"postal_code,omitempty" example:"94102"`

	// Latitude coordinate
	// @example 37.7749
	Latitude float64 `json:"latitude,omitempty" example:"37.7749"`

	// Longitude coordinate
	// @example -122.4194
	Longitude float64 `json:"longitude,omitempty" example:"-122.4194"`

	// Time zone
	// @example America/Los_Angeles
	TimeZone string `json:"timezone,omitempty" example:"America/Los_Angeles"`

	// Internet Service Provider
	// @example Comcast Cable Communications
	ISP string `json:"isp,omitempty" example:"Comcast Cable Communications"`

	// Autonomous System Number
	// @example 7922
	ASN uint `json:"asn,omitempty" example:"7922"`

	// ASN Organization name
	// @example COMCAST-7922
	ASNOrg string `json:"asn_org,omitempty" example:"COMCAST-7922"`

	// Whether IP is from a proxy
	// @example false
	IsProxy bool `json:"is_proxy,omitempty" example:"false"`

	// Whether IP is from a VPN
	// @example false
	IsVPN bool `json:"is_vpn,omitempty" example:"false"`

	// Whether IP is from Tor network
	// @example false
	IsTor bool `json:"is_tor,omitempty" example:"false"`
}
