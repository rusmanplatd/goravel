package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("mail", map[string]any{
		// Default Mail Driver
		//
		// This option controls the default mail driver that is used to send
		// any e-mails when a driver is not explicitly specified.
		"default": config.Env("MAIL_MAILER", "log"),

		// Mail Driver Configurations
		//
		// Here you may configure all of the mail drivers used by your application
		// plus their respective settings. Several examples have been configured for
		// you and you are free to add your own as your application requires.
		"mailers": map[string]any{
			"smtp": map[string]any{
				"transport":    "smtp",
				"host":         config.Env("MAIL_HOST", "smtp.mailgun.org"),
				"port":         config.Env("MAIL_PORT", 587),
				"encryption":   config.Env("MAIL_ENCRYPTION", "tls"),
				"username":     config.Env("MAIL_USERNAME"),
				"password":     config.Env("MAIL_PASSWORD"),
				"timeout":      config.Env("MAIL_TIMEOUT", 5),
				"local_domain": config.Env("MAIL_EHLO_DOMAIN"),
			},
			"ses": map[string]any{
				"transport": "ses",
			},
			"mailgun": map[string]any{
				"transport": "mailgun",
			},
			"log": map[string]any{
				"transport": "log",
				"channel":   config.Env("MAIL_LOG_CHANNEL"),
			},
			"array": map[string]any{
				"transport": "array",
			},
		},

		// Global "From" Address
		//
		// You may wish for all e-mails sent by your application to be sent from
		// the same address. Here, you may specify a name and address that is
		// used globally for all e-mails that are sent by your application.
		"from": map[string]any{
			"address": config.Env("MAIL_FROM_ADDRESS", "hello@example.com"),
			"name":    config.Env("MAIL_FROM_NAME", "Example"),
		},

		// Markdown Mail Settings
		//
		// If you are using Markdown based email rendering, you may configure your
		// theme and component paths here, allowing you to customize the design
		// of the emails. Or, you may simply stick with the Laravel defaults!
		"markdown": map[string]any{
			"theme": config.Env("MAIL_MARKDOWN_THEME", "default"),
			"paths": []string{
				"resources/views/vendor/mail",
			},
		},
	})
}
