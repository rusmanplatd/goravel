package routes

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"

	"goravel/app/http/controllers/web"
)

// Web routes
func Web() {
	// Get web controller instances
	authController := web.NewAuthController()
	tenantController := web.NewTenantController()
	roleController := web.NewRoleController()
	permissionController := web.NewPermissionController()

	// Authentication routes
	facades.Route().Group(func(router route.Router) {
		// Guest routes (no authentication required)
		router.Get("/login", authController.ShowLogin)
		router.Post("/login", authController.Login)
		router.Get("/register", authController.ShowRegister)
		router.Post("/register", authController.Register)
		router.Get("/forgot-password", authController.ShowForgotPassword)
		router.Post("/forgot-password", authController.ForgotPassword)
		router.Get("/reset-password", authController.ShowResetPassword)
		router.Post("/reset-password", authController.ResetPassword)

		// Protected routes (authentication required)
		router.Group(func(router route.Router) {
			// Apply auth middleware here if needed
			// router.Middleware("auth")

			// Dashboard
			router.Get("/dashboard", authController.ShowDashboard)
			router.Post("/logout", authController.Logout)

			// Tenant management
			router.Get("/tenants", tenantController.Index)
			router.Get("/tenants/create", tenantController.Create)
			router.Post("/tenants", tenantController.Store)
			router.Get("/tenants/{id}", tenantController.Show)
			router.Get("/tenants/{id}/edit", tenantController.Edit)
			router.Put("/tenants/{id}", tenantController.Update)
			router.Delete("/tenants/{id}", tenantController.Delete)

			// Role management (within tenant context)
			router.Get("/roles", roleController.Index)
			router.Get("/roles/create", roleController.Create)
			router.Post("/roles", roleController.Store)
			router.Get("/roles/{id}", roleController.Show)
			router.Get("/roles/{id}/edit", roleController.Edit)
			router.Put("/roles/{id}", roleController.Update)
			router.Delete("/roles/{id}", roleController.Delete)

			// Permission management (within tenant context)
			router.Get("/permissions", permissionController.Index)
			router.Get("/permissions/create", permissionController.Create)
			router.Post("/permissions", permissionController.Store)
			router.Get("/permissions/{id}/edit", permissionController.Edit)
			router.Put("/permissions/{id}", permissionController.Update)
			router.Delete("/permissions/{id}", permissionController.Destroy)
		})
	})

	// Default route
	facades.Route().Get("/", func(ctx http.Context) http.Response {
		return ctx.Response().Redirect(302, "/dashboard")
	})
}
