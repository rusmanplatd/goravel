package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("mail", map[string]any{
		// Default Mailer
		//
		// This option controls the default mailer that is used to send any email
		// messages sent by your application. Alternative mailers may be setup
		// and used as needed; however, this mailer will be used by default.

		"default": VaultConfig("secret/services/mail", "default", "log").(string),

		// Mailer Configurations
		//
		// Here you may configure all of the mailers used by your application plus
		// their respective settings. Several examples have been configured for
		// you and you are free to add your own as your application requires.

		"mailers": map[string]any{
			"smtp": map[string]any{
				"host":         VaultConfig("secret/services/mail", "host", "smtp.mailgun.org").(string),
				"port":         VaultConfig("secret/services/mail", "port", 587).(int),
				"encryption":   VaultConfig("secret/services/mail", "encryption", "tls").(string),
				"username":     VaultConfig("secret/services/mail", "username", "").(string),
				"password":     VaultConfig("secret/services/mail", "password", "").(string),
				"timeout":      VaultConfig("secret/services/mail", "timeout", 5).(int),
				"local_domain": VaultConfig("secret/services/mail", "local_domain", "").(string),
			},

			"ses": map[string]any{
				"key":    VaultConfig("secret/services/mail", "ses_key", "").(string),
				"secret": VaultConfig("secret/services/mail", "ses_secret", "").(string),
				"region": VaultConfig("secret/services/mail", "ses_region", "us-east-1").(string),
			},

			"log": map[string]any{
				"channel": VaultConfig("secret/services/mail", "log_channel", "").(string),
			},
		},

		// Global "From" Address
		//
		// You may wish for all e-mails sent by your application to be sent from
		// the same address. Here, you may specify a name and address that is
		// used globally for all e-mails that are sent by your application.

		"from": map[string]any{
			"address": VaultConfig("secret/services/mail", "from_address", "hello@example.com").(string),
			"name":    VaultConfig("secret/services/mail", "from_name", "Example").(string),
		},

		// Markdown Mail Settings
		//
		// If you are using Markdown based email rendering, you may configure your
		// theme and component paths here, allowing you to customize the design
		// of the emails. Or, you may simply stick with the Laravel defaults!

		"markdown": map[string]any{
			"theme": VaultConfig("secret/services/mail", "markdown_theme", "default").(string),
		},
	})
}
