package config

import (
	"github.com/goravel/framework/contracts/database/driver"

	"github.com/goravel/framework/facades"
	postgresfacades "github.com/goravel/postgres/facades"
)

func init() {
	config := facades.Config()
	config.Add("database", map[string]any{
		// Default database connection name
		"default": VaultConfig("secret/database/config", "default", "postgres").(string),

		// Database connections
		"connections": map[string]any{
			"postgres": map[string]any{
				"host":     VaultConfig("secret/database/postgres", "host", "127.0.0.1").(string),
				"port":     VaultConfig("secret/database/postgres", "port", 5432).(int),
				"database": VaultConfig("secret/database/postgres", "database", "forge").(string),
				"username": VaultConfig("secret/database/postgres", "username", "").(string),
				"password": VaultConfig("secret/database/postgres", "password", "").(string),
				"sslmode":  VaultConfig("secret/database/postgres", "sslmode", "disable").(string),
				"prefix":   VaultConfig("secret/database/postgres", "prefix", "").(string),
				"singular": VaultConfig("secret/database/postgres", "singular", false).(bool),
				"schema":   VaultConfig("secret/database/postgres", "schema", "public").(string),
				"via": func() (driver.Driver, error) {
					return postgresfacades.Postgres("postgres")
				},
			},
		},

		// Pool configuration
		"pool": map[string]any{
			// Sets the maximum number of connections in the idle
			// connection pool.
			//
			// If MaxOpenConns is greater than 0 but less than the new MaxIdleConns,
			// then the new MaxIdleConns will be reduced to match the MaxOpenConns limit.
			//
			// If n <= 0, no idle connections are retained.
			"max_idle_conns": VaultConfig("secret/database/pool", "max_idle_conns", 10).(int),
			// Sets the maximum number of open connections to the database.
			//
			// If MaxIdleConns is greater than 0 and the new MaxOpenConns is less than
			// MaxIdleConns, then MaxIdleConns will be reduced to match the new
			// MaxOpenConns limit.
			//
			// If n <= 0, then there is no limit on the number of open connections.
			"max_open_conns": VaultConfig("secret/database/pool", "max_open_conns", 100).(int),
			// Sets the maximum amount of time a connection may be idle.
			//
			// Expired connections may be closed lazily before reuse.
			//
			// If d <= 0, connections are not closed due to a connection's idle time.
			// Unit: Second
			"conn_max_idletime": VaultConfig("secret/database/pool", "conn_max_idletime", 3600).(int),
			// Sets the maximum amount of time a connection may be reused.
			//
			// Expired connections may be closed lazily before reuse.
			//
			// If d <= 0, connections are not closed due to a connection's age.
			// Unit: Second
			"conn_max_lifetime": VaultConfig("secret/database/pool", "conn_max_lifetime", 3600).(int),
		},

		// Sets the threshold for slow queries in milliseconds, the slow query will be logged.
		// Unit: Millisecond
		"slow_threshold": VaultConfig("secret/database/config", "slow_threshold", 200).(int),

		// Migration Repository Table
		//
		// This table keeps track of all the migrations that have already run for
		// your application. Using this information, we can determine which of
		// the migrations on disk haven't actually been run in the database.
		"migrations": map[string]any{
			"table": VaultConfig("secret/database/config", "migrations_table", "migrations").(string),
		},
		"redis": map[string]any{
			"default": map[string]any{
				"host":     VaultConfig("secret/database/redis", "host", "").(string),
				"password": VaultConfig("secret/database/redis", "password", "").(string),
				"port":     VaultConfig("secret/database/redis", "port", 6379).(int),
				"database": VaultConfig("secret/database/redis", "database", 0).(int),
			},
		},
	})
}
