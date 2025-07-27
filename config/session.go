package config

import (
	"goravel/app/services"

	"github.com/goravel/framework/contracts/session"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support/str"
)

func init() {
	config := facades.Config()
	config.Add("session", map[string]any{
		// Default Session Driver
		//
		// This option controls the default session "driver" that will be used on
		// requests. By default, we will use the lightweight native driver but
		// you may specify any of the other wonderful drivers provided here.
		//
		// Supported: "file", "cookie", "database", "redis", "custom"

		"default": VaultConfig("secret/session/config", "default", "database").(string),

		// Session Drivers
		//
		// Here you may configure the session drivers for your application. If you
		// only need one driver you may just remove the others from here.

		"drivers": map[string]any{
			"database": map[string]any{
				"driver":     "database",
				"connection": VaultConfig("secret/session/config", "connection", "default").(string),
				"table":      VaultConfig("secret/session/config", "table", "sessions").(string),
				"via": func() (session.Driver, error) {
					table := VaultConfig("secret/session/config", "table", "sessions").(string)
					connection := VaultConfig("secret/session/config", "connection", "default").(string)
					return services.NewDatabaseSessionDriver(table, connection), nil
				},
			},
			"file": map[string]any{
				"driver": "file",
				"path":   VaultConfig("secret/session/config", "file_path", "storage/framework/sessions").(string),
			},
			"redis": map[string]any{
				"driver":     "redis",
				"connection": VaultConfig("secret/session/config", "redis_connection", "default").(string),
			},
		},

		// Session Lifetime
		//
		// Here you may specify the number of minutes that you wish the session
		// to be allowed to remain idle before it expires. If you want them
		// to immediately expire on the browser closing, set that option.

		"lifetime": VaultConfig("secret/session/config", "lifetime", 120).(int),

		"expire_on_close": VaultConfig("secret/session/config", "expire_on_close", false).(bool),

		// Session Encryption
		//
		// This option allows you to easily specify that all of your session data
		// should be encrypted before it is stored. All encryption will be run
		// automatically by Goravel and you can use the Session like normal.

		"encrypt": VaultConfig("secret/session/config", "encrypt", false).(bool),

		// Session File Location
		//
		// When using the native session driver, we need a location where session
		// files may be stored. A default has been set for you but a different
		// location may be specified. This is only needed for file sessions.

		"files": VaultConfig("secret/session/config", "files", "storage/framework/sessions").(string),

		// Session Database Connection
		//
		// When using the "database" session driver, you may specify a connection that
		// should be used to manage these sessions. This should correspond to a
		// connection in your database configuration options.

		"connection": VaultConfig("secret/session/config", "connection", "").(string),

		// Session Database Table
		//
		// When using the "database" session driver, you may specify the table we
		// should use to manage the sessions. Of course, a sensible default is
		// provided for you; however, you are free to change this as needed.

		"table": VaultConfig("secret/session/config", "table", "sessions").(string),

		// Session Garbage Collection
		//
		// Some session drivers must manually sweep their storage location to get
		// rid of old sessions from storage. Here are the chances that it will
		// happen on a given request. By default, the odds are 2 out of 100.

		"lottery": []int{2, 100},

		// Session Garbage Collection Interval
		//
		// When using drivers that need to manually clean up expired sessions,
		// you can set the interval (in minutes) for the garbage collection.

		"gc_interval": VaultConfig("secret/session/config", "gc_interval", 30).(int),

		// Session Cookie Configuration
		//
		// Here you may configure the session cookie settings, including the
		// cookie name, path, domain, security, and httpOnly attributes.

		"cookie": VaultConfig("secret/session/config", "cookie", str.Of(config.GetString("app.name")).Snake().Lower().String()+"_session").(string),

		// Session Cookie Path
		//
		// The session cookie path determines the path for which the cookie will
		// be regarded as available. Typically, this will be the root path of
		// your application but you are free to change this when necessary.

		"path": VaultConfig("secret/session/config", "path", "/").(string),

		// Session Cookie Domain
		//
		// Here you may change the domain of the cookie used to identify a session
		// in your application. This will determine which domains the cookie is
		// available to in your application. A sensible default has been set.

		"domain": VaultConfig("secret/session/config", "domain", "").(string),

		// HTTPS Only Cookies
		//
		// By setting this option to true, session cookies will only be sent back
		// to the server if the browser has a HTTPS connection. This will keep
		// the cookie from being sent to you if it can not be done securely.

		"secure": VaultConfig("secret/session/config", "secure", false).(bool),

		// HTTP Access Only
		//
		// Setting this value to true will prevent JavaScript from accessing the
		// value of the cookie and the cookie will only be accessible through
		// the HTTP protocol. You are free to modify this option if needed.

		"http_only": VaultConfig("secret/session/config", "http_only", true).(bool),

		// Same-Site Cookies
		//
		// This option determines how your cookies behave when cross-site requests
		// take place, and can be used to mitigate CSRF attacks. By default, we
		// will set this value to "lax" since this is a secure default value.
		//
		// Supported: "lax", "strict", "none", null

		"same_site": VaultConfig("secret/session/config", "same_site", "lax").(string),
	})
}
