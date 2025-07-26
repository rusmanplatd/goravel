package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000083CreateUserProfilesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000083CreateUserProfilesTable) Signature() string {
	return "20250115000083_create_user_profiles_table"
}

// Up Run the migrations.
func (r *M20250115000083CreateUserProfilesTable) Up() error {
	return facades.Schema().Create("user_profiles", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique user profile identifier")
		table.Ulid("user_id").Comment("Reference to users table")

		// Personal Information
		table.String("first_name").Nullable().Comment("User's first name")
		table.String("middle_name").Nullable().Comment("User's middle name")
		table.String("last_name").Nullable().Comment("User's last name")
		table.String("display_name").Nullable().Comment("User's preferred display name")
		table.String("nickname").Nullable().Comment("User's nickname")
		table.String("gender").Nullable().Comment("User's gender")
		table.Date("birthdate").Nullable().Comment("User's birthdate (YYYY-MM-DD)")
		table.String("website").Nullable().Comment("User's personal website URL")
		table.String("bio").Nullable().Comment("User's biography/description")

		// Contact Information
		table.Boolean("phone_verified").Default(false).Comment("Whether user's phone is verified")
		table.TimestampTz("phone_verified_at").Nullable().Comment("When phone was verified")
		table.Boolean("email_verified").Default(false).Comment("Whether user's email is verified")

		// Location/Address Information
		table.String("street_address").Nullable().Comment("Street address")
		table.String("locality").Nullable().Comment("City/locality")
		table.String("region").Nullable().Comment("State/province/region")
		table.String("postal_code").Nullable().Comment("Postal/ZIP code")
		table.String("country_code").Nullable().Comment("ISO country code (US, CA, etc.)")
		table.String("formatted_address").Nullable().Comment("Full formatted address")

		// Location references to existing models
		table.Ulid("country_id").Nullable().Comment("Reference to countries table")
		table.Ulid("province_id").Nullable().Comment("Reference to provinces table")
		table.Ulid("city_id").Nullable().Comment("Reference to cities table")
		table.Ulid("district_id").Nullable().Comment("Reference to districts table")

		// Preferences
		table.String("timezone").Default("UTC").Comment("User's preferred timezone")
		table.String("locale").Default("en-US").Comment("User's preferred locale")
		table.String("language").Default("en").Comment("User's preferred language")
		table.String("currency").Default("USD").Comment("User's preferred currency")
		table.String("date_format").Default("Y-m-d").Comment("User's preferred date format")
		table.String("time_format").Default("H:i").Comment("User's preferred time format")

		// Account Information
		table.String("account_type").Default("personal").Comment("Account type (personal, business, etc.)")
		table.String("user_type").Default("user").Comment("User type (admin, user, etc.)")
		table.String("status").Default("active").Comment("User status (active, suspended, etc.)")

		// Social/Professional Information
		table.String("company").Nullable().Comment("User's company/organization")
		table.String("job_title").Nullable().Comment("User's job title")
		table.String("department").Nullable().Comment("User's department")
		table.String("employee_id").Nullable().Comment("Employee ID")
		table.Date("hire_date").Nullable().Comment("Hire date")

		// Additional Profile Data
		table.Text("profile_data").Nullable().Comment("Additional profile data as JSON")
		table.Text("preferences").Nullable().Comment("User preferences as JSON")
		table.Text("metadata").Nullable().Comment("Additional metadata as JSON")

		// Visibility/Privacy Settings
		table.Boolean("profile_public").Default(false).Comment("Whether profile is public")
		table.Boolean("show_email").Default(false).Comment("Whether to show email in profile")
		table.Boolean("show_phone").Default(false).Comment("Whether to show phone in profile")
		table.Boolean("show_address").Default(false).Comment("Whether to show address in profile")

		// Timestamps and audit fields
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Nullable().Comment("User who created profile")
		table.Ulid("updated_by").Nullable().Comment("User who updated profile")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted profile")

		// Primary key
		table.Primary("id")

		// Indexes
		table.Index("user_id")
		table.Index("phone_verified")
		table.Index("email_verified")
		table.Index("country_id")
		table.Index("province_id")
		table.Index("city_id")
		table.Index("district_id")
		table.Index("timezone")
		table.Index("locale")
		table.Index("account_type")
		table.Index("user_type")
		table.Index("status")
		table.Index("profile_public")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Unique constraint for user_id (one profile per user)
		table.Unique("user_id")

		// Foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("country_id").References("id").On("countries")
		table.Foreign("province_id").References("id").On("provinces")
		table.Foreign("city_id").References("id").On("cities")
		table.Foreign("district_id").References("id").On("districts")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000083CreateUserProfilesTable) Down() error {
	return facades.Schema().DropIfExists("user_profiles")
}
