package oidc

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/teamhanko/hanko/backend/v3/crypto/aes_gcm"
)

// codeData is what an authorization code stands for: sealed into the code by the memory store,
// or kept in a row behind a random handle by the Postgres store.
type codeData struct {
	JTI           string    `json:"jti"`
	ClientID      string    `json:"cid"`
	RedirectURI   string    `json:"ruri"`
	UserID        string    `json:"sub"`
	SessionID     string    `json:"sid"`
	Nonce         string    `json:"nonce,omitempty"`
	CodeChallenge string    `json:"cc,omitempty"`
	Scope         string    `json:"scope"`
	AuthTime      time.Time `json:"auth_time"`
	Exp           time.Time `json:"exp"`
}

var errBadCode = errors.New("invalid authorization code")

// CodeStore issues and redeems authorization codes.
type CodeStore interface {
	// Issue stores d and returns the code to send to the client.
	Issue(ctx context.Context, d codeData) (string, error)
	// Redeem returns a code's data exactly once. Unknown, tampered, expired and already used
	// codes return errBadCode; any other error means the store itself failed.
	Redeem(ctx context.Context, code string) (*codeData, error)
}

// memoryCodes seals codes with AES-GCM under Hanko's secrets.keys and tracks used ones in memory.
// That's exact for a single instance; a restart within a code's lifetime forgets used codes,
// but a replay would still need the client secret, the PKCE verifier, and a live session.
type memoryCodes struct {
	aead *aes_gcm.AESGCM
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

// codeKeyLabel separates the code-sealing keys from Hanko's own uses of secrets.keys.
const codeKeyLabel = "hankoid oidc authorization code v1"

func newMemoryCodes(keys []string) (*memoryCodes, error) {
	derived := make([]string, len(keys))
	for i, k := range keys {
		dk, err := hkdf.Key(sha256.New, []byte(k), nil, codeKeyLabel, 32)
		if err != nil {
			return nil, err
		}
		derived[i] = hex.EncodeToString(dk)
	}
	aead, err := aes_gcm.NewAESGCM(derived)
	if err != nil {
		return nil, err
	}
	return &memoryCodes{aead: aead, used: map[string]time.Time{}, now: time.Now}, nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Issue seals d into the code itself; nothing is stored.
func (c *memoryCodes) Issue(_ context.Context, d codeData) (string, error) {
	d.JTI = randomID()
	b, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	return c.aead.Encrypt(b)
}

// Redeem decrypts a code, checks expiry, and marks it used. A code can only be redeemed once.
func (c *memoryCodes) Redeem(_ context.Context, code string) (*codeData, error) {
	b, err := c.aead.Decrypt(code)
	if err != nil {
		return nil, errBadCode
	}
	var d codeData
	if err := json.Unmarshal(b, &d); err != nil || d.JTI == "" {
		return nil, errBadCode
	}
	now := c.now()
	if now.After(d.Exp) {
		return nil, errBadCode
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for jti, exp := range c.used {
		if now.After(exp) {
			delete(c.used, jti)
		}
	}
	if _, seen := c.used[d.JTI]; seen {
		return nil, errBadCode
	}
	c.used[d.JTI] = d.Exp
	return &d, nil
}
