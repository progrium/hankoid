package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLock is the pg_advisory_lock key held while migrating, so replicas starting
// together apply each migration once. It's "hankoid" in ASCII.
const migrationLock = 0x68616e6b6f6964

// OpenPostgres connects to Hanko's database with a small pool and checks the connection.
func OpenPostgres(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("oidc postgres: %w", err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc postgres: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("oidc postgres: %w", err)
	}
	return pool, nil
}

// Migrate creates the hankoid schema and applies any embedded migrations not yet recorded in
// hankoid.schema_migrations, each in its own transaction. It's safe to run concurrently and
// repeatedly. Hanko's own migrations ("hankoid migrate up") never touch this schema.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied []int, err error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(migrationLock)); err != nil {
		return nil, fmt.Errorf("migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", int64(migrationLock))
	}()
	if _, err := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS hankoid;
CREATE TABLE IF NOT EXISTS hankoid.schema_migrations (
  version    integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return nil, fmt.Errorf("create hankoid schema: %w", err)
	}
	done := map[int]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM hankoid.schema_migrations")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		done[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	migs, err := migrations()
	if err != nil {
		return nil, err
	}
	for _, m := range migs {
		if done[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO hankoid.schema_migrations (version) VALUES ($1)", m.version)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.name, err)
		}
		applied = append(applied, m.version)
	}
	return applied, nil
}

type migration struct {
	version int
	name    string
	sql     string
}

// migrations returns the embedded files, named NNNN_description.sql, in version order.
func migrations() ([]migration, error) {
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, n := range names {
		base := strings.TrimPrefix(n, "migrations/")
		num, _, ok := strings.Cut(base, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("bad migration file name %q", base)
		}
		b, err := migrationFiles.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: base, sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// PostgresCodes keeps authorization codes in hankoid.oidc_auth_codes. Codes are random handles;
// only their SHA-256 is stored. Redeeming is one conditional UPDATE, so a code works exactly once
// across restarts and any number of replicas.
type PostgresCodes struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewPostgresCodes returns a code store on pool. Run Migrate first.
func NewPostgresCodes(pool *pgxpool.Pool) *PostgresCodes {
	return &PostgresCodes{pool: pool, now: time.Now}
}

// maxCodeLen bounds what Redeem will hash; issued codes are 43 characters.
const maxCodeLen = 128

func hashCode(code string) []byte {
	sum := sha256.Sum256([]byte(code))
	return sum[:]
}

// Issue stores d under a new random code.
func (s *PostgresCodes) Issue(ctx context.Context, d codeData) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	_, err := s.pool.Exec(ctx, `INSERT INTO hankoid.oidc_auth_codes
  (code_hash, client_id, user_id, session_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at)
VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9, $10)`,
		hashCode(code), d.ClientID, d.UserID, d.SessionID, d.RedirectURI, d.Scope, d.Nonce, d.CodeChallenge, d.AuthTime, d.Exp)
	if err != nil {
		return "", fmt.Errorf("store code: %w", err)
	}
	return code, nil
}

// Redeem marks the code used and returns its data, unless it's unknown, expired, or already used.
func (s *PostgresCodes) Redeem(ctx context.Context, code string) (*codeData, error) {
	if code == "" || len(code) > maxCodeLen {
		return nil, errBadCode
	}
	var d codeData
	err := s.pool.QueryRow(ctx, `UPDATE hankoid.oidc_auth_codes
   SET used_at = $2
 WHERE code_hash = $1 AND used_at IS NULL AND expires_at > $2
RETURNING client_id, user_id, COALESCE(session_id, ''), redirect_uri, scope,
          COALESCE(nonce, ''), COALESCE(code_challenge, ''), auth_time, expires_at`,
		hashCode(code), s.now()).Scan(&d.ClientID, &d.UserID, &d.SessionID, &d.RedirectURI, &d.Scope,
		&d.Nonce, &d.CodeChallenge, &d.AuthTime, &d.Exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errBadCode
	}
	if err != nil {
		return nil, fmt.Errorf("redeem code: %w", err)
	}
	return &d, nil
}

// codeRetention is how long rows stay after expiring. Used rows are kept at least until their
// code expires, so replays are detected for a code's whole life.
const codeRetention = time.Hour

// DeleteExpired removes codes that expired more than an hour ago and returns how many.
func (s *PostgresCodes) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, "DELETE FROM hankoid.oidc_auth_codes WHERE expires_at < $1", s.now().Add(-codeRetention))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RunCleanup calls DeleteExpired every interval until ctx is done. Running it on every replica
// is harmless.
func (s *PostgresCodes) RunCleanup(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.DeleteExpired(ctx); err != nil && ctx.Err() == nil {
				log.Printf("oidc: delete expired codes: %v", err)
			}
		}
	}
}
