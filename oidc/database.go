package oidc

import (
	"errors"

	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"os"
	"strings"
)

// Database is the part of Hanko's top-level database section that the Postgres store needs.
// Unset fields fall back to Hanko's defaults, and Hanko's DATABASE_* environment variables
// override the file, so the provider connects exactly where Hanko does.
type Database struct {
	// Url mirrors Hanko's field name; see URL for the connection string actually used.
	Dialect  string `yaml:"dialect"`
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	Url      string `yaml:"url"`
}

// LoadDatabase reads the database section of a Hanko config file, with environment overrides.
func LoadDatabase(raw []byte) (Database, error) {
	var f struct {
		Database Database `yaml:"database"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return Database{}, fmt.Errorf("parse database config: %w", err)
	}
	f.Database.applyEnv()
	return f.Database, nil
}

func (d *Database) applyEnv() {
	for env, dst := range map[string]*string{
		"DATABASE_DIALECT":  &d.Dialect,
		"DATABASE_HOST":     &d.Host,
		"DATABASE_PORT":     &d.Port,
		"DATABASE_USER":     &d.User,
		"DATABASE_PASSWORD": &d.Password,
		"DATABASE_DATABASE": &d.Database,
		"DATABASE_URL":      &d.Url,
	} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
}

// URL returns a Postgres connection URL. Like Hanko, database.url wins over the other fields.
// Only Postgres is supported: the store relies on its schemas and advisory locks.
func (d Database) URL() (string, error) {
	if d.Url != "" {
		u, err := url.Parse(d.Url)
		if err != nil {
			return "", errors.New("database.url is not a valid URL")
		}
		switch u.Scheme {
		case "postgres", "postgresql":
		default:
			return "", fmt.Errorf("database.url must be a postgres:// URL, not %s://", u.Scheme)
		}
		return d.Url, nil
	}
	dialect := strings.ToLower(or(d.Dialect, "postgres"))
	if dialect != "postgres" && dialect != "postgresql" {
		return "", fmt.Errorf("database.dialect must be postgres, not %q", d.Dialect)
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(or(d.User, "hanko"), or(d.Password, "hanko")),
		Host:   net.JoinHostPort(or(d.Host, "localhost"), or(d.Port, "5432")),
		Path:   "/" + or(d.Database, "hanko"),
	}
	return u.String(), nil
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
