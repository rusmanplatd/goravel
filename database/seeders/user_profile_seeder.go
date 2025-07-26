package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type UserProfileSeeder struct{}

// Signature The unique signature for the seeder.
func (s *UserProfileSeeder) Signature() string {
	return "UserProfileSeeder"
}

// Run executes the seeder.
func (s *UserProfileSeeder) Run() error {
	// Get some existing users to create profiles for
	var users []models.User
	if err := facades.Orm().Query().Limit(5).Find(&users); err != nil {
		facades.Log().Error("Failed to fetch users for profile seeding", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if len(users) == 0 {
		facades.Log().Info("No users found to create profiles for")
		return nil
	}

	// Sample profile data
	profileData := []map[string]interface{}{
		{
			"first_name":     "John",
			"middle_name":    "Michael",
			"last_name":      "Doe",
			"display_name":   "Johnny",
			"nickname":       "JD",
			"gender":         "male",
			"birthdate":      "1990-01-15",
			"website":        "https://johndoe.com",
			"bio":            "Software engineer passionate about building great products",
			"phone_verified": true,
			"email_verified": true,
			"street_address": "123 Main St",
			"locality":       "New York",
			"region":         "NY",
			"postal_code":    "10001",
			"country_code":   "US",
			"timezone":       "America/New_York",
			"locale":         "en-US",
			"language":       "en",
			"currency":       "USD",
			"account_type":   "personal",
			"user_type":      "user",
			"status":         "active",
			"company":        "Acme Corporation",
			"job_title":      "Senior Software Engineer",
			"department":     "Engineering",
			"employee_id":    "EMP001",
		},
		{
			"first_name":     "Jane",
			"last_name":      "Smith",
			"display_name":   "Jane Smith",
			"gender":         "female",
			"birthdate":      "1985-05-20",
			"website":        "https://janesmith.dev",
			"bio":            "Full-stack developer and tech lead",
			"phone_verified": true,
			"email_verified": true,
			"street_address": "456 Oak Ave",
			"locality":       "San Francisco",
			"region":         "CA",
			"postal_code":    "94102",
			"country_code":   "US",
			"timezone":       "America/Los_Angeles",
			"locale":         "en-US",
			"language":       "en",
			"currency":       "USD",
			"account_type":   "business",
			"user_type":      "admin",
			"status":         "active",
			"company":        "Tech Innovations Inc",
			"job_title":      "Tech Lead",
			"department":     "Engineering",
			"employee_id":    "EMP002",
		},
		{
			"first_name":     "Carlos",
			"last_name":      "Rodriguez",
			"display_name":   "Carlos",
			"gender":         "male",
			"birthdate":      "1992-03-10",
			"bio":            "DevOps engineer specializing in cloud infrastructure",
			"phone_verified": false,
			"email_verified": true,
			"street_address": "789 Pine St",
			"locality":       "Austin",
			"region":         "TX",
			"postal_code":    "73301",
			"country_code":   "US",
			"timezone":       "America/Chicago",
			"locale":         "es-US",
			"language":       "es",
			"currency":       "USD",
			"account_type":   "personal",
			"user_type":      "user",
			"status":         "active",
			"company":        "Cloud Solutions LLC",
			"job_title":      "DevOps Engineer",
			"department":     "Operations",
			"employee_id":    "EMP003",
		},
		{
			"first_name":     "Emma",
			"last_name":      "Johnson",
			"display_name":   "Emma J.",
			"nickname":       "Em",
			"gender":         "female",
			"birthdate":      "1988-11-25",
			"website":        "https://emmajohnson.design",
			"bio":            "UX/UI designer with a passion for user-centered design",
			"phone_verified": true,
			"email_verified": true,
			"street_address": "321 Elm Street",
			"locality":       "Seattle",
			"region":         "WA",
			"postal_code":    "98101",
			"country_code":   "US",
			"timezone":       "America/Los_Angeles",
			"locale":         "en-US",
			"language":       "en",
			"currency":       "USD",
			"account_type":   "business",
			"user_type":      "user",
			"status":         "active",
			"company":        "Design Studio Pro",
			"job_title":      "Senior UX Designer",
			"department":     "Design",
			"employee_id":    "EMP004",
		},
		{
			"first_name":     "Ahmed",
			"middle_name":    "Hassan",
			"last_name":      "Al-Rashid",
			"display_name":   "Ahmed Al-Rashid",
			"gender":         "male",
			"birthdate":      "1987-07-08",
			"bio":            "Data scientist and machine learning engineer",
			"phone_verified": true,
			"email_verified": true,
			"street_address": "654 Cedar Lane",
			"locality":       "Boston",
			"region":         "MA",
			"postal_code":    "02101",
			"country_code":   "US",
			"timezone":       "America/New_York",
			"locale":         "ar-US",
			"language":       "ar",
			"currency":       "USD",
			"account_type":   "personal",
			"user_type":      "user",
			"status":         "active",
			"company":        "Data Analytics Corp",
			"job_title":      "Senior Data Scientist",
			"department":     "Research",
			"employee_id":    "EMP005",
		},
	}

	// Create profiles for existing users
	for i, user := range users {
		if i >= len(profileData) {
			break
		}

		data := profileData[i]

		// Parse birthdate
		var birthdate *time.Time
		if birthdateStr, ok := data["birthdate"].(string); ok {
			if parsed, err := time.Parse("2006-01-02", birthdateStr); err == nil {
				birthdate = &parsed
			}
		}

		// Parse hire date (set to 1 year ago)
		hireDate := time.Now().AddDate(-1, 0, 0)

		// Parse phone verified at
		var phoneVerifiedAt *time.Time
		if data["phone_verified"].(bool) {
			verifiedTime := time.Now().AddDate(0, -6, 0) // 6 months ago
			phoneVerifiedAt = &verifiedTime
		}

		// Create formatted address
		formattedAddress := ""
		if street, ok := data["street_address"].(string); ok {
			formattedAddress = street
			if locality, ok := data["locality"].(string); ok {
				if region, ok := data["region"].(string); ok {
					if postal, ok := data["postal_code"].(string); ok {
						formattedAddress += fmt.Sprintf("\n%s, %s %s", locality, region, postal)
					}
				}
			}
			if country, ok := data["country_code"].(string); ok {
				formattedAddress += fmt.Sprintf("\n%s", country)
			}
		}

		profile := models.UserProfile{
			UserID:           user.ID,
			FirstName:        getStringPtr(data["first_name"]),
			MiddleName:       getStringPtr(data["middle_name"]),
			LastName:         getStringPtr(data["last_name"]),
			DisplayName:      getStringPtr(data["display_name"]),
			Nickname:         getStringPtr(data["nickname"]),
			Gender:           getStringPtr(data["gender"]),
			Birthdate:        birthdate,
			Website:          getStringPtr(data["website"]),
			Bio:              getStringPtr(data["bio"]),
			PhoneVerified:    data["phone_verified"].(bool),
			PhoneVerifiedAt:  phoneVerifiedAt,
			EmailVerified:    data["email_verified"].(bool),
			StreetAddress:    getStringPtr(data["street_address"]),
			Locality:         getStringPtr(data["locality"]),
			Region:           getStringPtr(data["region"]),
			PostalCode:       getStringPtr(data["postal_code"]),
			CountryCode:      getStringPtr(data["country_code"]),
			FormattedAddress: &formattedAddress,
			Timezone:         data["timezone"].(string),
			Locale:           data["locale"].(string),
			Language:         data["language"].(string),
			Currency:         data["currency"].(string),
			AccountType:      data["account_type"].(string),
			UserType:         data["user_type"].(string),
			Status:           data["status"].(string),
			Company:          getStringPtr(data["company"]),
			JobTitle:         getStringPtr(data["job_title"]),
			Department:       getStringPtr(data["department"]),
			EmployeeID:       getStringPtr(data["employee_id"]),
			HireDate:         &hireDate,
		}

		// Set some sample profile data
		profileDataMap := map[string]interface{}{
			"interests": []string{"technology", "music", "travel"},
			"skills":    []string{"golang", "javascript", "python", "docker"},
			"hobbies":   []string{"reading", "hiking", "photography"},
		}
		if err := profile.SetProfileData(profileDataMap); err != nil {
			facades.Log().Warning("Failed to set profile data", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
		}

		// Set some preferences
		preferencesMap := map[string]interface{}{
			"theme": "dark",
			"notifications": map[string]bool{
				"email": true,
				"push":  false,
				"sms":   true,
			},
			"privacy": map[string]bool{
				"show_profile": true,
				"show_email":   false,
				"show_phone":   false,
			},
		}
		if err := profile.SetPreferences(preferencesMap); err != nil {
			facades.Log().Warning("Failed to set preferences", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
		}

		// Set metadata
		metadataMap := map[string]interface{}{
			"source":        "seeder",
			"created_by":    "system",
			"last_sync":     time.Now().Format(time.RFC3339),
			"profile_score": 85,
		}
		if err := profile.SetMetadata(metadataMap); err != nil {
			facades.Log().Warning("Failed to set metadata", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
		}

		// Create the profile
		if err := facades.Orm().Query().Create(&profile); err != nil {
			facades.Log().Error("Failed to create user profile", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
			continue
		}

		facades.Log().Info("Created user profile", map[string]interface{}{
			"user_id":    user.ID,
			"profile_id": profile.ID,
			"name":       profile.GetFullName(),
		})
	}

	facades.Log().Info("User profile seeding completed", map[string]interface{}{
		"profiles_created": len(users),
	})

	return nil
}

// Helper function to convert string to *string
func getStringPtr(value interface{}) *string {
	if value == nil {
		return nil
	}
	if str, ok := value.(string); ok && str != "" {
		return &str
	}
	return nil
}
