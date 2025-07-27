package web

import (
	"github.com/goravel/framework/contracts/http"
)

type DriveController struct{}

func NewDriveController() *DriveController {
	return &DriveController{}
}

// Index shows the main drive interface
func (dc *DriveController) Index(ctx http.Context) http.Response {
	data := map[string]interface{}{
		"Title":   "Drive",
		"AppName": "Goravel Drive",
	}

	return ctx.Response().View().Make("drive/index.tmpl", data)
}
