# Google OAuth2 Integration Setup Guide

This guide explains how to set up and use the Google OAuth2 integration in your Goravel application.

## 🚀 Overview

The Google OAuth2 integration allows users to sign in using their Google accounts, providing a seamless authentication experience. This implementation includes:

- **Google OAuth2 Authentication Flow**: Complete OAuth2 authorization code flow with PKCE support
- **User Account Linking**: Automatic linking of Google accounts to existing users or creation of new accounts
- **Session Management**: Secure session handling for authenticated users
- **Security Features**: CSRF protection, state validation, and secure token handling

## 📋 Prerequisites

Before setting up Google OAuth2, you need:

1. A Google Cloud Console project
2. OAuth2 credentials (Client ID and Client Secret)
3. Configured redirect URIs in Google Cloud Console

## 🔧 Google Cloud Console Setup

### Step 1: Create a Google Cloud Project

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API (if not already enabled)

### Step 2: Configure OAuth Consent Screen

1. Navigate to **APIs & Services** > **OAuth consent screen**
2. Choose **External** user type (or **Internal** if using Google Workspace)
3. Fill in the required information:
   - **App name**: Your application name
   - **User support email**: Your support email
   - **Developer contact information**: Your email address
4. Add your domain to **Authorized domains** if applicable
5. Save and continue through the scopes and test users sections

### Step 3: Create OAuth2 Credentials

1. Navigate to **APIs & Services** > **Credentials**
2. Click **Create Credentials** > **OAuth client ID**
3. Choose **Web application** as the application type
4. Configure the following:
   - **Name**: A descriptive name for your OAuth client
   - **Authorized JavaScript origins**: 
     - `http://localhost:3000` (for development)
     - `https://yourdomain.com` (for production)
   - **Authorized redirect URIs**:
     - `http://localhost:3000/auth/google/callback` (for development)
     - `https://yourdomain.com/auth/google/callback` (for production)
5. Click **Create** and save your **Client ID** and **Client Secret**

## ⚙️ Application Configuration

### Step 1: Environment Variables

Add the following variables to your `.env` file:

```env
# Google OAuth2 Configuration
GOOGLE_OAUTH_ENABLED=true
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_REDIRECT_URL=http://localhost:3000/auth/google/callback
```

### Step 2: Database Migration

The Google OAuth2 fields have been added to the users table via migration. If you haven't run migrations yet:

```bash
go run . artisan migrate
```

This adds the following fields to the `users` table:
- `avatar` (VARCHAR): User's profile picture URL from Google
- `google_id` (VARCHAR): Google's unique identifier for the user

## 🎯 Usage

### For End Users

1. **Sign In**: Users can click "Sign in with Google" on the login page
2. **Account Linking**: 
   - If a user with the same email exists, the Google account is linked
   - If no user exists, a new account is created
3. **Profile Information**: Avatar and profile information are automatically synced from Google

### For Developers

#### Available Routes

```go
// Public routes
GET  /auth/google           // Redirect to Google OAuth
GET  /auth/google/callback  // Handle OAuth callback

// Protected routes (require authentication)
POST /auth/google/unlink    // Unlink Google account
```

#### Using the Google OAuth Service

```go
// Create service instance
googleOAuthService := services.NewGoogleOAuthService()

// Check if Google OAuth is enabled
if googleOAuthService.IsEnabled() {
    // Generate authorization URL
    state := googleOAuthService.GenerateState()
    authURL := googleOAuthService.GetAuthURL(state)
    
    // Handle callback
    user, err := googleOAuthService.HandleCallback(ctx, code)
    if err != nil {
        // Handle error
    }
}
```

#### User Model Extensions

The User model now includes:

```go
type User struct {
    // ... existing fields ...
    
    // User's profile picture/avatar URL
    Avatar string `json:"avatar,omitempty"`
    
    // Google OAuth ID for Google sign-in integration
    GoogleID *string `gorm:"unique" json:"google_id,omitempty"`
}
```

## 🔒 Security Features

### CSRF Protection
- State parameter validation prevents CSRF attacks
- Session-based state storage ensures security

### Token Security
- Secure token exchange using OAuth2 authorization code flow
- JWT tokens for session management
- Automatic token refresh capabilities

### Account Security
- Email verification through Google OAuth
- Account linking based on email addresses
- Secure user profile synchronization

## 🧪 Testing

### Development Testing

1. Start the development server:
   ```bash
   go run . artisan serve
   ```

2. Visit `http://localhost:3000/login`
3. Click "Sign in with Google"
4. Complete the OAuth flow in your browser
5. Verify successful authentication and redirection

### Manual Testing Checklist

- [ ] Google OAuth button appears on login page when enabled
- [ ] Clicking the button redirects to Google's consent screen
- [ ] Successful authentication creates/links user account
- [ ] User profile information is populated from Google
- [ ] Session is properly established after OAuth
- [ ] Account unlinking works correctly
- [ ] Error handling works for various failure scenarios

## 🐛 Troubleshooting

### Common Issues

#### "OAuth is not enabled" Error
- Check that `GOOGLE_OAUTH_ENABLED=true` in your `.env` file
- Verify the configuration is loaded correctly

#### "Invalid redirect URI" Error
- Ensure the redirect URI in Google Cloud Console matches exactly
- Check for trailing slashes or protocol mismatches
- Verify the domain is authorized in Google Cloud Console

#### "Invalid client ID" Error
- Double-check the `GOOGLE_CLIENT_ID` in your `.env` file
- Ensure the client ID is copied correctly from Google Cloud Console

#### "Invalid state parameter" Error
- This usually indicates a CSRF attack or session issues
- Check that sessions are working properly
- Ensure the state parameter is being stored and retrieved correctly

#### Database Connection Issues
- Verify database connection settings
- Ensure migrations have been run
- Check that the `users` table has the required `avatar` and `google_id` columns

### Debug Mode

Enable debug logging to troubleshoot issues:

```env
APP_DEBUG=true
LOG_LEVEL=debug
```

Check the logs in `storage/logs/` for detailed error information.

## 🔧 Customization

### Custom Scopes

To request additional Google API scopes, modify the configuration in `config/auth.go`:

```go
"scopes": []string{
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    // Add additional scopes here
    "https://www.googleapis.com/auth/calendar.readonly",
},
```

### Custom User Information

To handle additional user information from Google, extend the `GoogleUserInfo` struct in `app/services/google_oauth_service.go`:

```go
type GoogleUserInfo struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    VerifiedEmail bool   `json:"verified_email"`
    Name          string `json:"name"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Picture       string `json:"picture"`
    Locale        string `json:"locale"`
    // Add additional fields as needed
}
```

### Custom Redirect Logic

Modify the redirect logic in `GoogleOAuthController.Callback()` to customize where users are redirected after successful authentication.

## 📚 Additional Resources

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Google Cloud Console](https://console.cloud.google.com/)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)
- [Goravel Framework Documentation](https://www.goravel.dev/)

## 🎉 Conclusion

Your Goravel application now has a complete Google OAuth2 integration that provides:

- ✅ Secure Google OAuth2 authentication flow
- ✅ Automatic user account creation and linking
- ✅ Profile information synchronization
- ✅ Session management and security
- ✅ Comprehensive error handling
- ✅ Production-ready configuration

Users can now seamlessly sign in with their Google accounts, and developers have full control over the authentication flow and user management. 