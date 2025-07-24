package seeders

import "github.com/goravel/framework/facades"

type DatabaseSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *DatabaseSeeder) Signature() string {
	return "DatabaseSeeder"
}

// Run executes the seeder logic.
func (s *DatabaseSeeder) Run() error {
	facades.Log().Info("Starting DatabaseSeeder...")
	// ... existing code ...
	facades.Log().Info("DatabaseSeeder completed. No actions performed.")
	return nil
}
