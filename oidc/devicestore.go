package oidc

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceStore keeps device authorizations (RFC 8628), approved devices, rotating refresh tokens
// and gateway tickets in the hankoid schema. It needs Postgres: pending logins must survive
// restarts and be visible to every replica.
type DeviceStore struct {
	pool    *pgxpool.Pool
	codeKey []byte // HMAC key for user codes
	now     func() time.Time
}

// userCodeKeyLabel separates the user-code HMAC key from other uses of secrets.keys.
const userCodeKeyLabel = "hankoid oidc user code v1"

// NewDeviceStore returns a device store on pool. secretKeys are Hanko's secrets.keys; the first
// one keys the user-code HMAC. Run Migrate first.
func NewDeviceStore(pool *pgxpool.Pool, secretKeys []string) (*DeviceStore, error) {
	if len(secretKeys) == 0 {
		return nil, errors.New("device store: secrets.keys must be set")
	}
	k, err := hkdf.Key(sha256.New, []byte(secretKeys[0]), nil, userCodeKeyLabel, 32)
	if err != nil {
		return nil, err
	}
	return &DeviceStore{pool: pool, codeKey: k, now: time.Now}, nil
}

// Grant states.
const (
	grantPending  = "pending"
	grantApproved = "approved"
	grantDenied   = "denied"
	grantConsumed = "consumed"
)

// DeviceGrant is a device authorization request.
type DeviceGrant struct {
	ClientID     string
	Scope        string
	Resource     string
	Status       string
	RequesterIP  string
	RequesterGeo string
	RequesterUA  string
	DeviceName   string
	UserID       string
	SessionID    string
	ApproverIP   string
	AuthTime     time.Time
	Interval     time.Duration
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Device is an approved device: one refresh-token chain the user can see and revoke.
type Device struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	ClientID   string     `json:"client_id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	AuthTime   time.Time  `json:"auth_time"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedIP  string     `json:"created_ip"`
	LastUsedAt time.Time  `json:"last_used_at"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

// User codes: 8 characters from RFC 8628 §6.1's 20 consonants (about 34.6 bits), shown as XXXX-XXXX.
const (
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen      = 8
)

var errNotFound = errors.New("not found")

// NormalizeUserCode uppercases a user code and drops dashes and spaces. ok is false when any other
// character is outside the alphabet or the length is wrong, so a typo never reaches the database.
func NormalizeUserCode(s string) (code string, ok bool) {
	var b strings.Builder
	for _, c := range strings.ToUpper(s) {
		switch {
		case c == '-' || c == ' ' || c == '\t':
		case strings.ContainsRune(userCodeAlphabet, c):
			b.WriteRune(c)
		default:
			return "", false
		}
	}
	code = b.String()
	return code, len(code) == userCodeLen
}

// FormatUserCode shows a normalized code as XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != userCodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

func newUserCode() (string, error) {
	b := make([]byte, userCodeLen)
	out := make([]byte, userCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		// 256 % 20 != 0, so reject the biased tail.
		for b[i] >= 240 {
			var one [1]byte
			if _, err := rand.Read(one[:]); err != nil {
				return "", err
			}
			b[i] = one[0]
		}
		out[i] = userCodeAlphabet[int(b[i])%len(userCodeAlphabet)]
	}
	return string(out), nil
}

func (s *DeviceStore) hashUserCode(code string) []byte {
	m := hmac.New(sha256.New, s.codeKey)
	m.Write([]byte(code))
	return m.Sum(nil)
}

func randomToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// CreateGrant stores a new pending grant and returns its device code and (normalized) user code.
func (s *DeviceStore) CreateGrant(ctx context.Context, g DeviceGrant) (deviceCode, userCode string, err error) {
	deviceCode, err = randomToken("")
	if err != nil {
		return "", "", err
	}
	for attempt := 0; attempt < 5; attempt++ {
		userCode, err = newUserCode()
		if err != nil {
			return "", "", err
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO hankoid.oidc_device_grants
  (device_code_hash, user_code_hash, client_id, scope, resource, requester_ip, requester_geo, requester_ua,
   device_name, interval_s, created_at, expires_at)
VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, $11, $12)`,
			hashCode(deviceCode), s.hashUserCode(userCode), g.ClientID, g.Scope, g.Resource, g.RequesterIP,
			g.RequesterGeo, g.RequesterUA, g.DeviceName, int(g.Interval/time.Second), g.CreatedAt, g.ExpiresAt)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" && strings.Contains(pe.ConstraintName, "user_code") {
			continue // user code collision: try another
		}
		if err != nil {
			return "", "", fmt.Errorf("store device grant: %w", err)
		}
		return deviceCode, userCode, nil
	}
	return "", "", errors.New("store device grant: could not find a free user code")
}

const grantColumns = `client_id, scope, COALESCE(resource, ''), status, requester_ip, COALESCE(requester_geo, ''),
  COALESCE(requester_ua, ''), COALESCE(device_name, ''), COALESCE(user_id, ''), COALESCE(approved_session, ''),
  COALESCE(approver_ip, ''), COALESCE(auth_time, 'epoch'), interval_s, created_at, expires_at`

func scanGrant(row pgx.Row) (*DeviceGrant, error) {
	var g DeviceGrant
	var interval int
	err := row.Scan(&g.ClientID, &g.Scope, &g.Resource, &g.Status, &g.RequesterIP, &g.RequesterGeo, &g.RequesterUA,
		&g.DeviceName, &g.UserID, &g.SessionID, &g.ApproverIP, &g.AuthTime, &interval, &g.CreatedAt, &g.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	g.Interval = time.Duration(interval) * time.Second
	return &g, nil
}

// PendingGrant returns the unexpired pending grant for a normalized user code, or errNotFound.
func (s *DeviceStore) PendingGrant(ctx context.Context, userCode string) (*DeviceGrant, error) {
	return scanGrant(s.pool.QueryRow(ctx, `SELECT `+grantColumns+` FROM hankoid.oidc_device_grants
 WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > $2`, s.hashUserCode(userCode), s.now()))
}

// Decide approves or denies a pending, unexpired grant. errNotFound means it was already decided,
// expired, or never existed.
func (s *DeviceStore) Decide(ctx context.Context, userCode string, approve bool, userID, sessionID, approverIP string, authTime time.Time) error {
	status := grantDenied
	if approve {
		status = grantApproved
	}
	tag, err := s.pool.Exec(ctx, `UPDATE hankoid.oidc_device_grants
   SET status = $2, user_id = $3, approved_session = NULLIF($4, ''), approver_ip = NULLIF($5, ''),
       auth_time = $6, decided_at = $7
 WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > $7`,
		s.hashUserCode(userCode), status, userID, sessionID, approverIP, authTime, s.now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errNotFound
	}
	return nil
}

// PollResult is what a token-endpoint poll of a device code found.
type PollResult int

const (
	PollUnknown  PollResult = iota // no such code, another client's, or already consumed
	PollSlowDown                   // polled faster than the grant's interval; it grew by 5 seconds
	PollPending
	PollDenied
	PollExpired
	PollApproved
)

// Poll records a poll of deviceCode by clientID and reports the grant's state. An approved grant
// is returned but not consumed; call Consume to issue its device.
func (s *DeviceStore) Poll(ctx context.Context, deviceCode, clientID string) (PollResult, *DeviceGrant, error) {
	if deviceCode == "" || len(deviceCode) > maxCodeLen {
		return PollUnknown, nil, nil
	}
	var res PollResult
	var grant *DeviceGrant
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var lastPolled *time.Time
		var g DeviceGrant
		var interval int
		err := tx.QueryRow(ctx, `SELECT `+grantColumns+`, last_polled_at FROM hankoid.oidc_device_grants
 WHERE device_code_hash = $1 FOR UPDATE`, hashCode(deviceCode)).Scan(&g.ClientID, &g.Scope, &g.Resource, &g.Status,
			&g.RequesterIP, &g.RequesterGeo, &g.RequesterUA, &g.DeviceName, &g.UserID, &g.SessionID, &g.ApproverIP,
			&g.AuthTime, &interval, &g.CreatedAt, &g.ExpiresAt, &lastPolled)
		if errors.Is(err, pgx.ErrNoRows) {
			res = PollUnknown
			return nil
		}
		if err != nil {
			return err
		}
		g.Interval = time.Duration(interval) * time.Second
		grant = &g
		now := s.now()
		switch {
		case g.ClientID != clientID || g.Status == grantConsumed:
			res = PollUnknown
			return nil
		case !now.Before(g.ExpiresAt):
			res = PollExpired
			return nil
		case lastPolled != nil && now.Sub(*lastPolled) < g.Interval:
			res = PollSlowDown
			g.Interval += 5 * time.Second
			_, err := tx.Exec(ctx, `UPDATE hankoid.oidc_device_grants SET interval_s = $2, last_polled_at = $3
 WHERE device_code_hash = $1`, hashCode(deviceCode), int(g.Interval/time.Second), now)
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE hankoid.oidc_device_grants SET last_polled_at = $2 WHERE device_code_hash = $1`,
			hashCode(deviceCode), now); err != nil {
			return err
		}
		switch g.Status {
		case grantApproved:
			res = PollApproved
		case grantDenied:
			res = PollDenied
		default:
			res = PollPending
		}
		return nil
	})
	return res, grant, err
}

// NewDevice describes the device and first refresh token to create when a grant is consumed.
type NewDevice struct {
	Name         string
	IP           string
	ExpiresAt    *time.Time // absolute lifetime, or nil
	RefreshToken string     // "" issues none
	RefreshExp   time.Time
}

// Consume marks an approved grant consumed and creates its device (and first refresh token) in
// one transaction. errNotFound means another poll consumed it first.
func (s *DeviceStore) Consume(ctx context.Context, deviceCode string, nd NewDevice) (*Device, error) {
	var d *Device
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now()
		var g DeviceGrant
		err := tx.QueryRow(ctx, `UPDATE hankoid.oidc_device_grants SET status = 'consumed'
 WHERE device_code_hash = $1 AND status = 'approved' AND expires_at > $2
RETURNING client_id, scope, user_id, auth_time, requester_ip`, hashCode(deviceCode), now).
			Scan(&g.ClientID, &g.Scope, &g.UserID, &g.AuthTime, &g.RequesterIP)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		name := nd.Name
		if name == "" {
			name = "Unnamed device"
		}
		ip := nd.IP
		if ip == "" {
			ip = g.RequesterIP
		}
		d = &Device{ID: newUUID(), UserID: g.UserID, ClientID: g.ClientID, Name: name, Scope: g.Scope,
			AuthTime: g.AuthTime, CreatedAt: now, CreatedIP: ip, LastUsedAt: now, LastUsedIP: ip, ExpiresAt: nd.ExpiresAt}
		if _, err := tx.Exec(ctx, `INSERT INTO hankoid.oidc_devices
  (id, user_id, client_id, name, scope, auth_time, created_at, created_ip, last_used_at, last_used_ip, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $8, $9)`,
			d.ID, d.UserID, d.ClientID, d.Name, d.Scope, d.AuthTime, now, ip, d.ExpiresAt); err != nil {
			return err
		}
		if nd.RefreshToken != "" {
			_, err := tx.Exec(ctx, `INSERT INTO hankoid.oidc_refresh_tokens (token_hash, device_id, issued_at, expires_at)
VALUES ($1, $2, $3, $4)`, hashCode(nd.RefreshToken), d.ID, now, nd.RefreshExp)
			return err
		}
		return nil
	})
	return d, err
}

// RefreshResult is the outcome of presenting a refresh token.
type RefreshResult int

const (
	RefreshInvalid RefreshResult = iota // unknown, expired, or its device is revoked or expired
	RefreshRotated                      // exchanged for a new token
	RefreshReused                       // replayed after the grace window: the device is now revoked
)

// Refresh exchanges a refresh token for newToken. A token rotated less than grace ago is treated
// as a concurrent refresh: the device's outstanding token is replaced and newToken issued. Older
// replays revoke the device (RFC 9700 §4.14.2).
func (s *DeviceStore) Refresh(ctx context.Context, token, newToken string, newExp time.Time, ip string, grace time.Duration) (RefreshResult, *Device, error) {
	if token == "" || len(token) > maxCodeLen {
		return RefreshInvalid, nil, nil
	}
	res := RefreshInvalid
	var dev *Device
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now()
		var deviceID string
		var expires time.Time
		var rotated *time.Time
		err := tx.QueryRow(ctx, `SELECT device_id::text, expires_at, rotated_at FROM hankoid.oidc_refresh_tokens
 WHERE token_hash = $1 FOR UPDATE`, hashCode(token)).Scan(&deviceID, &expires, &rotated)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceColumns+` FROM hankoid.oidc_devices WHERE id = $1 FOR UPDATE`, deviceID))
		if err != nil {
			return err
		}
		dev = d
		if d.RevokedAt != nil || (d.ExpiresAt != nil && !now.Before(*d.ExpiresAt)) {
			return nil
		}
		if rotated != nil && now.Sub(*rotated) >= grace {
			res = RefreshReused
			return revokeDeviceTx(ctx, tx, d.ID, "reuse", now)
		}
		if rotated == nil && !now.Before(expires) {
			return nil
		}
		// Retire the device's outstanding token(s): this one, or on a grace-window replay, the
		// successor another caller was just given.
		if _, err := tx.Exec(ctx, `UPDATE hankoid.oidc_refresh_tokens SET rotated_at = $2
 WHERE device_id = $1 AND rotated_at IS NULL`, d.ID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO hankoid.oidc_refresh_tokens (token_hash, device_id, issued_at, expires_at)
VALUES ($1, $2, $3, $4)`, hashCode(newToken), d.ID, now, newExp); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE hankoid.oidc_devices SET last_used_at = $2, last_used_ip = NULLIF($3, '') WHERE id = $1`,
			d.ID, now, ip); err != nil {
			return err
		}
		d.LastUsedAt, d.LastUsedIP = now, ip
		res = RefreshRotated
		return nil
	})
	if err != nil {
		return RefreshInvalid, nil, err
	}
	return res, dev, nil
}

const deviceColumns = `id::text, user_id, client_id, name, scope, auth_time, created_at, created_ip, last_used_at,
  COALESCE(last_used_ip, ''), expires_at, revoked_at, COALESCE(revoked_by, '')`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.UserID, &d.ClientID, &d.Name, &d.Scope, &d.AuthTime, &d.CreatedAt, &d.CreatedIP,
		&d.LastUsedAt, &d.LastUsedIP, &d.ExpiresAt, &d.RevokedAt, &d.RevokedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	return &d, err
}

func revokeDeviceTx(ctx context.Context, tx pgx.Tx, id, by string, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE hankoid.oidc_devices SET revoked_at = $2, revoked_by = $3
 WHERE id = $1 AND revoked_at IS NULL`, id, now, by); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM hankoid.oidc_refresh_tokens WHERE device_id = $1`, id)
	return err
}

func validUUID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// Device returns a device by ID, revoked or not.
func (s *DeviceStore) Device(ctx context.Context, id string) (*Device, error) {
	if !validUUID(id) {
		return nil, errNotFound
	}
	return scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM hankoid.oidc_devices WHERE id = $1`, id))
}

// DeviceActive reports whether a device exists, isn't revoked, and hasn't passed its absolute lifetime.
func (s *DeviceStore) DeviceActive(ctx context.Context, id string) (bool, error) {
	d, err := s.Device(ctx, id)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return d.RevokedAt == nil && (d.ExpiresAt == nil || s.now().Before(*d.ExpiresAt)), nil
}

// UserDevices lists a user's unrevoked devices, most recently used first.
func (s *DeviceStore) UserDevices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+` FROM hankoid.oidc_devices
 WHERE user_id = $1 AND revoked_at IS NULL ORDER BY last_used_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// RevokeDevice revokes one device. With userID set, only that user's device is revoked. It reports
// whether a device was revoked by this call.
func (s *DeviceStore) RevokeDevice(ctx context.Context, id, userID, by string) (bool, error) {
	if !validUUID(id) {
		return false, nil
	}
	var revoked bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE hankoid.oidc_devices SET revoked_at = $2, revoked_by = $3
 WHERE id = $1 AND revoked_at IS NULL AND ($4 = '' OR user_id = $4)`, id, s.now(), by, userID)
		if err != nil {
			return err
		}
		revoked = tag.RowsAffected() == 1
		if revoked {
			_, err = tx.Exec(ctx, `DELETE FROM hankoid.oidc_refresh_tokens WHERE device_id = $1`, id)
		}
		return err
	})
	return revoked, err
}

// RevokeUserDevices revokes all of a user's devices and returns their IDs.
func (s *DeviceStore) RevokeUserDevices(ctx context.Context, userID, by string) ([]string, error) {
	var ids []string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		ids = nil
		rows, err := tx.Query(ctx, `UPDATE hankoid.oidc_devices SET revoked_at = $2, revoked_by = $3
 WHERE user_id = $1 AND revoked_at IS NULL RETURNING id::text`, userID, s.now(), by)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM hankoid.oidc_refresh_tokens WHERE device_id::text = ANY($1)`, ids)
		return err
	})
	return ids, err
}

// RevokeByRefreshToken revokes the device a refresh token belongs to (RFC 7009), if any.
func (s *DeviceStore) RevokeByRefreshToken(ctx context.Context, token, clientID string) (string, error) {
	if token == "" || len(token) > maxCodeLen {
		return "", nil
	}
	var id string
	err := s.pool.QueryRow(ctx, `SELECT d.id::text FROM hankoid.oidc_refresh_tokens t
  JOIN hankoid.oidc_devices d ON d.id = t.device_id WHERE t.token_hash = $1 AND d.client_id = $2`,
		hashCode(token), clientID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	ok, err := s.RevokeDevice(ctx, id, "", "logout")
	if !ok {
		id = ""
	}
	return id, err
}

// Revocation is a revoked device, as listed by the revocations feed.
type Revocation struct {
	DeviceID  string    `json:"device_id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason"`
}

// revocationOverlap re-sends revocations this close to the cursor, so a revocation committed late
// by another instance (or under clock skew) isn't missed. Consumers treat the feed as idempotent.
const revocationOverlap = 30 * time.Second

// RevokedSince lists devices revoked after since (minus a small overlap), oldest first, and the
// cursor to pass next time.
func (s *DeviceStore) RevokedSince(ctx context.Context, since time.Time, limit int) ([]Revocation, time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text, user_id, client_id, revoked_at, COALESCE(revoked_by, '')
  FROM hankoid.oidc_devices WHERE revoked_at > $1 ORDER BY revoked_at LIMIT $2`, since.Add(-revocationOverlap), limit)
	if err != nil {
		return nil, since, err
	}
	defer rows.Close()
	out := []Revocation{}
	cursor := since
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.DeviceID, &r.UserID, &r.ClientID, &r.RevokedAt, &r.Reason); err != nil {
			return nil, since, err
		}
		if r.RevokedAt.After(cursor) {
			cursor = r.RevokedAt
		}
		out = append(out, r)
	}
	return out, cursor, rows.Err()
}

// Ticket is what a gateway ticket stands for.
type Ticket struct {
	Resource string
	UserID   string
	DeviceID string
	ClientID string
	Username string
}

// CreateTicket stores a single-use ticket for t that expires after ttl.
func (s *DeviceStore) CreateTicket(ctx context.Context, t Ticket, ttl time.Duration) (string, error) {
	ticket, err := randomToken("hktk_")
	if err != nil {
		return "", err
	}
	var device any
	if t.DeviceID != "" {
		device = t.DeviceID
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO hankoid.gateway_tickets
  (ticket_hash, resource, user_id, device_id, client_id, username, expires_at)
VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), $7)`, hashCode(ticket), t.Resource, t.UserID, device, t.ClientID, t.Username, s.now().Add(ttl))
	if err != nil {
		return "", fmt.Errorf("store ticket: %w", err)
	}
	return ticket, nil
}

// RedeemTicket returns a ticket's data exactly once, for the resource it was issued for.
func (s *DeviceStore) RedeemTicket(ctx context.Context, ticket, resource string) (*Ticket, error) {
	if ticket == "" || len(ticket) > maxCodeLen {
		return nil, errNotFound
	}
	var t Ticket
	err := s.pool.QueryRow(ctx, `UPDATE hankoid.gateway_tickets SET used_at = $3
 WHERE ticket_hash = $1 AND resource = $2 AND used_at IS NULL AND expires_at > $3
RETURNING resource, user_id, COALESCE(device_id::text, ''), client_id, COALESCE(username, '')`,
		hashCode(ticket), resource, s.now()).Scan(&t.Resource, &t.UserID, &t.DeviceID, &t.ClientID, &t.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Retention for rows that no longer do anything.
const (
	grantRetention         = time.Hour
	rotatedTokenRetention  = 24 * time.Hour
	revokedDeviceRetention = 30 * 24 * time.Hour
)

// DeleteExpired removes expired grants, tickets, and refresh tokens, and long-revoked devices.
func (s *DeviceStore) DeleteExpired(ctx context.Context) error {
	now := s.now()
	for _, q := range []struct {
		sql string
		at  time.Time
	}{
		{"DELETE FROM hankoid.oidc_device_grants WHERE expires_at < $1", now.Add(-grantRetention)},
		{"DELETE FROM hankoid.gateway_tickets WHERE expires_at < $1", now.Add(-grantRetention)},
		{"DELETE FROM hankoid.oidc_refresh_tokens WHERE expires_at < $1 OR rotated_at < $1", now.Add(-rotatedTokenRetention)},
		{"DELETE FROM hankoid.oidc_devices WHERE revoked_at < $1 OR expires_at < $1", now.Add(-revokedDeviceRetention)},
	} {
		if _, err := s.pool.Exec(ctx, q.sql, q.at); err != nil {
			return err
		}
	}
	return nil
}
