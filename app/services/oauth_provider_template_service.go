package services

import (
	"encoding/json"
	"fmt"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthProviderTemplateService struct{}

type ProviderTemplate struct {
	Name              string            `json:"name"`
	DisplayName       string            `json:"display_name"`
	Description       string            `json:"description"`
	IconURL           string            `json:"icon_url"`
	ButtonColor       string            `json:"button_color"`
	AuthorizationURL  string            `json:"authorization_url"`
	TokenURL          string            `json:"token_url"`
	UserinfoURL       string            `json:"userinfo_url"`
	Scopes            []string          `json:"scopes"`
	UserinfoMapping   map[string]string `json:"userinfo_mapping"`
	Documentation     string            `json:"documentation"`
	SetupInstructions []SetupStep       `json:"setup_instructions"`
	RequiredFields    []string          `json:"required_fields"`
	OptionalFields    []string          `json:"optional_fields"`
}

type SetupStep struct {
	Step        int    `json:"step"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action,omitempty"`
	URL         string `json:"url,omitempty"`
}

func NewOAuthProviderTemplateService() *OAuthProviderTemplateService {
	return &OAuthProviderTemplateService{}
}

// GetAvailableTemplates returns all available provider templates
func (s *OAuthProviderTemplateService) GetAvailableTemplates() []ProviderTemplate {
	return []ProviderTemplate{
		s.getGoogleTemplate(),
		s.getGitHubTemplate(),
		s.getMicrosoftTemplate(),
		s.getFacebookTemplate(),
		s.getTwitterTemplate(),
		s.getLinkedInTemplate(),
		s.getDiscordTemplate(),
		s.getSlackTemplate(),
		s.getAppleTemplate(),
		s.getAmazonTemplate(),
	}
}

// GetTemplate returns a specific provider template by name
func (s *OAuthProviderTemplateService) GetTemplate(name string) (*ProviderTemplate, error) {
	templates := s.GetAvailableTemplates()
	for _, template := range templates {
		if template.Name == name {
			return &template, nil
		}
	}
	return nil, fmt.Errorf("template not found: %s", name)
}

// CreateProviderFromTemplate creates an OAuth provider from a template
func (s *OAuthProviderTemplateService) CreateProviderFromTemplate(templateName, clientID, clientSecret, redirectURL string) (*models.OAuthIdentityProvider, error) {
	template, err := s.GetTemplate(templateName)
	if err != nil {
		return nil, err
	}

	// Convert scopes to JSON
	scopesJSON, err := json.Marshal(template.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes: %w", err)
	}

	// Convert userinfo mapping to JSON
	mappingJSON, err := json.Marshal(template.UserinfoMapping)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal userinfo mapping: %w", err)
	}

	provider := &models.OAuthIdentityProvider{
		Name:             template.Name,
		DisplayName:      template.DisplayName,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		RedirectURL:      redirectURL,
		Scopes:           string(scopesJSON),
		AuthorizationURL: template.AuthorizationURL,
		TokenURL:         template.TokenURL,
		UserinfoURL:      template.UserinfoURL,
		UserinfoMapping:  string(mappingJSON),
		Enabled:          true,
		SortOrder:        999,
	}

	if template.IconURL != "" {
		provider.IconURL = &template.IconURL
	}
	if template.ButtonColor != "" {
		provider.ButtonColor = &template.ButtonColor
	}

	// Save to database
	err = facades.Orm().Query().Create(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	facades.Log().Info("OAuth provider created from template", map[string]interface{}{
		"template":     templateName,
		"provider_id":  provider.ID,
		"display_name": provider.DisplayName,
	})

	return provider, nil
}

// Template definitions

func (s *OAuthProviderTemplateService) getGoogleTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "google",
		DisplayName:      "Google",
		Description:      "Sign in with Google using OAuth 2.0",
		IconURL:          "https://developers.google.com/identity/images/g-logo.png",
		ButtonColor:      "#4285f4",
		AuthorizationURL: "https://accounts.google.com/o/oauth2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		UserinfoURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:           []string{"openid", "profile", "email"},
		UserinfoMapping: map[string]string{
			"id":     "id",
			"email":  "email",
			"name":   "name",
			"avatar": "picture",
		},
		Documentation: "https://developers.google.com/identity/protocols/oauth2",
		SetupInstructions: []SetupStep{
			{1, "Create Google Cloud Project", "Go to Google Cloud Console and create a new project", "navigate", "https://console.cloud.google.com/"},
			{2, "Enable Google+ API", "Enable the Google+ API for your project", "", ""},
			{3, "Create OAuth 2.0 Credentials", "Create OAuth 2.0 client credentials", "", ""},
			{4, "Configure Authorized Redirect URIs", "Add your callback URL to authorized redirect URIs", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getGitHubTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "github",
		DisplayName:      "GitHub",
		Description:      "Sign in with GitHub using OAuth 2.0",
		IconURL:          "https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png",
		ButtonColor:      "#333333",
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserinfoURL:      "https://api.github.com/user",
		Scopes:           []string{"user:email"},
		UserinfoMapping: map[string]string{
			"id":       "id",
			"email":    "email",
			"name":     "name",
			"username": "login",
			"avatar":   "avatar_url",
		},
		Documentation: "https://docs.github.com/en/developers/apps/building-oauth-apps",
		SetupInstructions: []SetupStep{
			{1, "Go to GitHub Settings", "Navigate to your GitHub account settings", "navigate", "https://github.com/settings/applications/new"},
			{2, "Create OAuth App", "Register a new OAuth application", "", ""},
			{3, "Configure Application", "Set application name, homepage URL, and callback URL", "", ""},
			{4, "Get Client Credentials", "Copy the Client ID and Client Secret", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getMicrosoftTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "microsoft",
		DisplayName:      "Microsoft",
		Description:      "Sign in with Microsoft using OAuth 2.0",
		IconURL:          "https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png",
		ButtonColor:      "#00a1f1",
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserinfoURL:      "https://graph.microsoft.com/v1.0/me",
		Scopes:           []string{"openid", "profile", "email"},
		UserinfoMapping: map[string]string{
			"id":     "id",
			"email":  "mail",
			"name":   "displayName",
			"avatar": "photo",
		},
		Documentation: "https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow",
		SetupInstructions: []SetupStep{
			{1, "Register App in Azure", "Go to Azure Portal and register a new application", "navigate", "https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade"},
			{2, "Configure Authentication", "Add platform and redirect URIs", "", ""},
			{3, "Generate Client Secret", "Create a new client secret in Certificates & secrets", "", ""},
			{4, "Set API Permissions", "Add required Microsoft Graph permissions", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getFacebookTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "facebook",
		DisplayName:      "Facebook",
		Description:      "Sign in with Facebook using OAuth 2.0",
		IconURL:          "https://upload.wikimedia.org/wikipedia/commons/5/51/Facebook_f_logo_%282019%29.svg",
		ButtonColor:      "#1877f2",
		AuthorizationURL: "https://www.facebook.com/v18.0/dialog/oauth",
		TokenURL:         "https://graph.facebook.com/v18.0/oauth/access_token",
		UserinfoURL:      "https://graph.facebook.com/v18.0/me",
		Scopes:           []string{"email", "public_profile"},
		UserinfoMapping: map[string]string{
			"id":     "id",
			"email":  "email",
			"name":   "name",
			"avatar": "picture.data.url",
		},
		Documentation: "https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow",
		SetupInstructions: []SetupStep{
			{1, "Create Facebook App", "Go to Facebook Developers and create a new app", "navigate", "https://developers.facebook.com/apps/"},
			{2, "Add Facebook Login", "Add Facebook Login product to your app", "", ""},
			{3, "Configure OAuth Settings", "Set valid OAuth redirect URIs", "", ""},
			{4, "Get App Credentials", "Copy App ID and App Secret", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getTwitterTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "twitter",
		DisplayName:      "Twitter",
		Description:      "Sign in with Twitter using OAuth 2.0",
		IconURL:          "https://abs.twimg.com/icons/apple-touch-icon-192x192.png",
		ButtonColor:      "#1da1f2",
		AuthorizationURL: "https://twitter.com/i/oauth2/authorize",
		TokenURL:         "https://api.twitter.com/2/oauth2/token",
		UserinfoURL:      "https://api.twitter.com/2/users/me",
		Scopes:           []string{"tweet.read", "users.read"},
		UserinfoMapping: map[string]string{
			"id":       "data.id",
			"name":     "data.name",
			"username": "data.username",
			"avatar":   "data.profile_image_url",
		},
		Documentation: "https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code",
		SetupInstructions: []SetupStep{
			{1, "Create Twitter App", "Go to Twitter Developer Portal and create a new app", "navigate", "https://developer.twitter.com/en/portal/dashboard"},
			{2, "Configure OAuth 2.0", "Enable OAuth 2.0 in app settings", "", ""},
			{3, "Set Callback URLs", "Add your callback URL to app settings", "", ""},
			{4, "Get API Keys", "Copy Client ID and Client Secret", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getLinkedInTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "linkedin",
		DisplayName:      "LinkedIn",
		Description:      "Sign in with LinkedIn using OAuth 2.0",
		IconURL:          "https://upload.wikimedia.org/wikipedia/commons/c/ca/LinkedIn_logo_initials.png",
		ButtonColor:      "#0077b5",
		AuthorizationURL: "https://www.linkedin.com/oauth/v2/authorization",
		TokenURL:         "https://www.linkedin.com/oauth/v2/accessToken",
		UserinfoURL:      "https://api.linkedin.com/v2/people/~",
		Scopes:           []string{"r_liteprofile", "r_emailaddress"},
		UserinfoMapping: map[string]string{
			"id":     "id",
			"name":   "localizedFirstName",
			"avatar": "profilePicture.displayImage",
		},
		Documentation: "https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow",
		SetupInstructions: []SetupStep{
			{1, "Create LinkedIn App", "Go to LinkedIn Developer Portal and create a new app", "navigate", "https://www.linkedin.com/developers/apps/new"},
			{2, "Configure OAuth 2.0", "Add OAuth 2.0 redirect URLs", "", ""},
			{3, "Request API Access", "Request access to required APIs", "", ""},
			{4, "Get Client Credentials", "Copy Client ID and Client Secret", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getDiscordTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "discord",
		DisplayName:      "Discord",
		Description:      "Sign in with Discord using OAuth 2.0",
		IconURL:          "https://assets-global.website-files.com/6257adef93867e50d84d30e2/636e0a6a49cf127bf92de1e2_icon_clyde_blurple_RGB.png",
		ButtonColor:      "#5865f2",
		AuthorizationURL: "https://discord.com/api/oauth2/authorize",
		TokenURL:         "https://discord.com/api/oauth2/token",
		UserinfoURL:      "https://discord.com/api/users/@me",
		Scopes:           []string{"identify", "email"},
		UserinfoMapping: map[string]string{
			"id":       "id",
			"email":    "email",
			"name":     "username",
			"username": "username",
			"avatar":   "avatar",
		},
		Documentation: "https://discord.com/developers/docs/topics/oauth2",
		SetupInstructions: []SetupStep{
			{1, "Create Discord App", "Go to Discord Developer Portal and create a new application", "navigate", "https://discord.com/developers/applications"},
			{2, "Configure OAuth2", "Add redirect URIs in OAuth2 settings", "", ""},
			{3, "Set Scopes", "Select required OAuth2 scopes", "", ""},
			{4, "Get Credentials", "Copy Client ID and Client Secret", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getSlackTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "slack",
		DisplayName:      "Slack",
		Description:      "Sign in with Slack using OAuth 2.0",
		IconURL:          "https://a.slack-edge.com/80588/marketing/img/icons/icon_slack_hash_colored.png",
		ButtonColor:      "#4a154b",
		AuthorizationURL: "https://slack.com/oauth/v2/authorize",
		TokenURL:         "https://slack.com/api/oauth.v2.access",
		UserinfoURL:      "https://slack.com/api/users.identity",
		Scopes:           []string{"identity.basic", "identity.email"},
		UserinfoMapping: map[string]string{
			"id":     "user.id",
			"email":  "user.email",
			"name":   "user.name",
			"avatar": "user.image_192",
		},
		Documentation: "https://api.slack.com/authentication/oauth-v2",
		SetupInstructions: []SetupStep{
			{1, "Create Slack App", "Go to Slack API and create a new app", "navigate", "https://api.slack.com/apps/new"},
			{2, "Configure OAuth", "Add redirect URLs in OAuth & Permissions", "", ""},
			{3, "Set Scopes", "Add required OAuth scopes", "", ""},
			{4, "Install App", "Install the app to get credentials", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getAppleTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "apple",
		DisplayName:      "Apple",
		Description:      "Sign in with Apple using OAuth 2.0",
		IconURL:          "https://developer.apple.com/assets/elements/icons/sign-in-with-apple/sign-in-with-apple.svg",
		ButtonColor:      "#000000",
		AuthorizationURL: "https://appleid.apple.com/auth/authorize",
		TokenURL:         "https://appleid.apple.com/auth/token",
		UserinfoURL:      "", // Apple provides user info in the ID token
		Scopes:           []string{"name", "email"},
		UserinfoMapping: map[string]string{
			"id":    "sub",
			"email": "email",
			"name":  "name",
		},
		Documentation: "https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api",
		SetupInstructions: []SetupStep{
			{1, "Register App ID", "Create an App ID in Apple Developer Console", "navigate", "https://developer.apple.com/account/resources/identifiers/list"},
			{2, "Enable Sign in with Apple", "Enable Sign in with Apple capability", "", ""},
			{3, "Create Service ID", "Create a Services ID for web authentication", "", ""},
			{4, "Configure Domains", "Add your domain and redirect URLs", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}

func (s *OAuthProviderTemplateService) getAmazonTemplate() ProviderTemplate {
	return ProviderTemplate{
		Name:             "amazon",
		DisplayName:      "Amazon",
		Description:      "Sign in with Amazon using OAuth 2.0",
		IconURL:          "https://m.media-amazon.com/images/G/01/lwa/btnLWA_gold_156x32.png",
		ButtonColor:      "#ff9900",
		AuthorizationURL: "https://www.amazon.com/ap/oa",
		TokenURL:         "https://api.amazon.com/auth/o2/token",
		UserinfoURL:      "https://api.amazon.com/user/profile",
		Scopes:           []string{"profile"},
		UserinfoMapping: map[string]string{
			"id":     "user_id",
			"email":  "email",
			"name":   "name",
			"avatar": "picture",
		},
		Documentation: "https://developer.amazon.com/docs/login-with-amazon/web-docs.html",
		SetupInstructions: []SetupStep{
			{1, "Create Amazon App", "Go to Login with Amazon Console and create a new app", "navigate", "https://developer.amazon.com/lwa/sp/overview.html"},
			{2, "Configure Web Settings", "Add allowed JavaScript origins and return URLs", "", ""},
			{3, "Get API Keys", "Copy Client ID and Client Secret", "", ""},
			{4, "Test Integration", "Test the OAuth flow with your application", "", ""},
		},
		RequiredFields: []string{"client_id", "client_secret", "redirect_url"},
		OptionalFields: []string{"icon_url", "button_color"},
	}
}
