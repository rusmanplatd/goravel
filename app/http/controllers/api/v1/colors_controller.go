package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/responses"
)

type ColorsController struct{}

func NewColorsController() *ColorsController {
	return &ColorsController{}
}

// Get returns the color definitions for calendars and events
// @Summary Get color definitions
// @Description Returns the color definitions for calendars and events
// @Tags colors
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Router /colors [get]
func (cc *ColorsController) Get(ctx http.Context) http.Response {
	// Google Calendar color definitions
	response := map[string]interface{}{
		"kind":    "calendar#colors",
		"updated": time.Now().Format(time.RFC3339),
		"calendar": map[string]interface{}{
			"1": map[string]interface{}{
				"background": "#ac725e",
				"foreground": "#1d1d1d",
			},
			"2": map[string]interface{}{
				"background": "#d06b64",
				"foreground": "#1d1d1d",
			},
			"3": map[string]interface{}{
				"background": "#f83a22",
				"foreground": "#1d1d1d",
			},
			"4": map[string]interface{}{
				"background": "#fa573c",
				"foreground": "#1d1d1d",
			},
			"5": map[string]interface{}{
				"background": "#ff7537",
				"foreground": "#1d1d1d",
			},
			"6": map[string]interface{}{
				"background": "#ffad46",
				"foreground": "#1d1d1d",
			},
			"7": map[string]interface{}{
				"background": "#42d692",
				"foreground": "#1d1d1d",
			},
			"8": map[string]interface{}{
				"background": "#16a765",
				"foreground": "#1d1d1d",
			},
			"9": map[string]interface{}{
				"background": "#7bd148",
				"foreground": "#1d1d1d",
			},
			"10": map[string]interface{}{
				"background": "#b3dc6c",
				"foreground": "#1d1d1d",
			},
			"11": map[string]interface{}{
				"background": "#fbe983",
				"foreground": "#1d1d1d",
			},
			"12": map[string]interface{}{
				"background": "#fad165",
				"foreground": "#1d1d1d",
			},
			"13": map[string]interface{}{
				"background": "#92e1c0",
				"foreground": "#1d1d1d",
			},
			"14": map[string]interface{}{
				"background": "#9fe1e7",
				"foreground": "#1d1d1d",
			},
			"15": map[string]interface{}{
				"background": "#9fc6e7",
				"foreground": "#1d1d1d",
			},
			"16": map[string]interface{}{
				"background": "#4986e7",
				"foreground": "#1d1d1d",
			},
			"17": map[string]interface{}{
				"background": "#9a9cff",
				"foreground": "#1d1d1d",
			},
			"18": map[string]interface{}{
				"background": "#b99aff",
				"foreground": "#1d1d1d",
			},
			"19": map[string]interface{}{
				"background": "#c2c2c2",
				"foreground": "#1d1d1d",
			},
			"20": map[string]interface{}{
				"background": "#cabdbf",
				"foreground": "#1d1d1d",
			},
			"21": map[string]interface{}{
				"background": "#cca6ac",
				"foreground": "#1d1d1d",
			},
			"22": map[string]interface{}{
				"background": "#f691b2",
				"foreground": "#1d1d1d",
			},
			"23": map[string]interface{}{
				"background": "#cd74e6",
				"foreground": "#1d1d1d",
			},
			"24": map[string]interface{}{
				"background": "#a47ae2",
				"foreground": "#1d1d1d",
			},
		},
		"event": map[string]interface{}{
			"1": map[string]interface{}{
				"background": "#a4bdfc",
				"foreground": "#1d1d1d",
			},
			"2": map[string]interface{}{
				"background": "#7ae7bf",
				"foreground": "#1d1d1d",
			},
			"3": map[string]interface{}{
				"background": "#dbadff",
				"foreground": "#1d1d1d",
			},
			"4": map[string]interface{}{
				"background": "#ff887c",
				"foreground": "#1d1d1d",
			},
			"5": map[string]interface{}{
				"background": "#fbd75b",
				"foreground": "#1d1d1d",
			},
			"6": map[string]interface{}{
				"background": "#ffb878",
				"foreground": "#1d1d1d",
			},
			"7": map[string]interface{}{
				"background": "#46d6db",
				"foreground": "#1d1d1d",
			},
			"8": map[string]interface{}{
				"background": "#e1e1e1",
				"foreground": "#1d1d1d",
			},
			"9": map[string]interface{}{
				"background": "#5484ed",
				"foreground": "#1d1d1d",
			},
			"10": map[string]interface{}{
				"background": "#51b749",
				"foreground": "#1d1d1d",
			},
			"11": map[string]interface{}{
				"background": "#dc2127",
				"foreground": "#1d1d1d",
			},
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetCalendarColors returns available calendar colors
// @Summary Get calendar colors
// @Description Returns available calendar colors for selection
// @Tags colors
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Router /colors/calendar [get]
func (cc *ColorsController) GetCalendarColors(ctx http.Context) http.Response {
	colors := map[string]interface{}{
		"1":  map[string]string{"background": "#ac725e", "foreground": "#1d1d1d", "name": "Cocoa"},
		"2":  map[string]string{"background": "#d06b64", "foreground": "#1d1d1d", "name": "Flamingo"},
		"3":  map[string]string{"background": "#f83a22", "foreground": "#1d1d1d", "name": "Tomato"},
		"4":  map[string]string{"background": "#fa573c", "foreground": "#1d1d1d", "name": "Tangerine"},
		"5":  map[string]string{"background": "#ff7537", "foreground": "#1d1d1d", "name": "Pumpkin"},
		"6":  map[string]string{"background": "#ffad46", "foreground": "#1d1d1d", "name": "Mango"},
		"7":  map[string]string{"background": "#42d692", "foreground": "#1d1d1d", "name": "Eucalyptus"},
		"8":  map[string]string{"background": "#16a765", "foreground": "#1d1d1d", "name": "Basil"},
		"9":  map[string]string{"background": "#7bd148", "foreground": "#1d1d1d", "name": "Pistachio"},
		"10": map[string]string{"background": "#b3dc6c", "foreground": "#1d1d1d", "name": "Avocado"},
		"11": map[string]string{"background": "#fbe983", "foreground": "#1d1d1d", "name": "Citron"},
		"12": map[string]string{"background": "#fad165", "foreground": "#1d1d1d", "name": "Banana"},
		"13": map[string]string{"background": "#92e1c0", "foreground": "#1d1d1d", "name": "Sage"},
		"14": map[string]string{"background": "#9fe1e7", "foreground": "#1d1d1d", "name": "Peacock"},
		"15": map[string]string{"background": "#9fc6e7", "foreground": "#1d1d1d", "name": "Cobalt"},
		"16": map[string]string{"background": "#4986e7", "foreground": "#1d1d1d", "name": "Blueberry"},
		"17": map[string]string{"background": "#9a9cff", "foreground": "#1d1d1d", "name": "Lavender"},
		"18": map[string]string{"background": "#b99aff", "foreground": "#1d1d1d", "name": "Wisteria"},
		"19": map[string]string{"background": "#c2c2c2", "foreground": "#1d1d1d", "name": "Graphite"},
		"20": map[string]string{"background": "#cabdbf", "foreground": "#1d1d1d", "name": "Birch"},
		"21": map[string]string{"background": "#cca6ac", "foreground": "#1d1d1d", "name": "Beige"},
		"22": map[string]string{"background": "#f691b2", "foreground": "#1d1d1d", "name": "Cherry Blossom"},
		"23": map[string]string{"background": "#cd74e6", "foreground": "#1d1d1d", "name": "Grape"},
		"24": map[string]string{"background": "#a47ae2", "foreground": "#1d1d1d", "name": "Amethyst"},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      colors,
		Timestamp: time.Now(),
	})
}

// GetEventColors returns available event colors
// @Summary Get event colors
// @Description Returns available event colors for selection
// @Tags colors
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Router /colors/event [get]
func (cc *ColorsController) GetEventColors(ctx http.Context) http.Response {
	colors := map[string]interface{}{
		"1":  map[string]string{"background": "#a4bdfc", "foreground": "#1d1d1d", "name": "Lavender"},
		"2":  map[string]string{"background": "#7ae7bf", "foreground": "#1d1d1d", "name": "Sage"},
		"3":  map[string]string{"background": "#dbadff", "foreground": "#1d1d1d", "name": "Grape"},
		"4":  map[string]string{"background": "#ff887c", "foreground": "#1d1d1d", "name": "Flamingo"},
		"5":  map[string]string{"background": "#fbd75b", "foreground": "#1d1d1d", "name": "Banana"},
		"6":  map[string]string{"background": "#ffb878", "foreground": "#1d1d1d", "name": "Tangerine"},
		"7":  map[string]string{"background": "#46d6db", "foreground": "#1d1d1d", "name": "Peacock"},
		"8":  map[string]string{"background": "#e1e1e1", "foreground": "#1d1d1d", "name": "Graphite"},
		"9":  map[string]string{"background": "#5484ed", "foreground": "#1d1d1d", "name": "Blueberry"},
		"10": map[string]string{"background": "#51b749", "foreground": "#1d1d1d", "name": "Basil"},
		"11": map[string]string{"background": "#dc2127", "foreground": "#1d1d1d", "name": "Tomato"},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      colors,
		Timestamp: time.Now(),
	})
}
