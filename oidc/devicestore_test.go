package oidc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// testDeviceStore returns a device store on the test database with empty device tables, and a
// settable clock.
func testDeviceStore(t *testing.T) (*DeviceStore, *time.Time) {
	t.Helper()
	pool := testPool(t)
	if _, err := pool.Exec(context.Background(), `TRUNCATE hankoid.oidc_device_grants, hankoid.oidc_refresh_tokens,
  hankoid.oidc_devices, hankoid.gateway_tickets`); err != nil {
		t.Fatal(err)
	}
	s, err := NewDeviceStore(pool, []string{"0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestUserCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := newUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := NormalizeUserCode(FormatUserCode(c)); !ok || n != c {
			t.Fatalf("round trip %q -> %q %v", c, n, ok)
		}
		for _, r := range c {
			if !strings.ContainsRune(userCodeAlphabet, r) {
				t.Fatalf("%q has %q outside the alphabet", c, r)
			}
		}
		seen[c] = true
	}
	if len(seen) < 199 {
		t.Errorf("only %d distinct codes in 200", len(seen))
	}
	for in, want := range map[string]string{"bcdf-ghjk": "BCDFGHJK", " BCDF GHJK ": "BCDFGHJK"} {
		if got, ok := NormalizeUserCode(in); !ok || got != want {
			t.Errorf("%q -> %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"BCDF-GHJ", "BCDF-GHJKL", "BCDF-GH0K", "ABCD-EFGH", ""} {
		if _, ok := NormalizeUserCode(in); ok {
			t.Errorf("%q should be rejected", in)
		}
	}
}

func newGrant(t *testing.T, s *DeviceStore) (deviceCode, userCode string) {
	t.Helper()
	now := s.now()
	dc, uc, err := s.CreateGrant(context.Background(), DeviceGrant{ClientID: "cli", Scope: "openid offline_access",
		RequesterIP: "203.0.113.7", DeviceName: "laptop", Interval: 5 * time.Second, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return dc, uc
}

func TestDeviceGrantLifecycle(t *testing.T) {
	s, now := testDeviceStore(t)
	ctx := context.Background()
	dc, uc := newGrant(t, s)

	if g, err := s.PendingGrant(ctx, uc); err != nil || g.ClientID != "cli" || g.DeviceName != "laptop" || g.RequesterIP != "203.0.113.7" {
		t.Fatalf("pending grant: %+v %v", g, err)
	}
	if res, _, _ := s.Poll(ctx, dc, "other"); res != PollUnknown {
		t.Errorf("another client's poll: %v", res)
	}
	if res, _, _ := s.Poll(ctx, dc, "cli"); res != PollPending {
		t.Errorf("first poll: %v", res)
	}
	*now = now.Add(2 * time.Second)
	if res, g, _ := s.Poll(ctx, dc, "cli"); res != PollSlowDown || g.Interval != 10*time.Second {
		t.Errorf("fast poll: %v %v", res, g.Interval)
	}
	*now = now.Add(6 * time.Second) // under the new 10s interval
	if res, _, _ := s.Poll(ctx, dc, "cli"); res != PollSlowDown {
		t.Errorf("poll under the grown interval: %v", res)
	}
	if err := s.Decide(ctx, uc, true, "alice", "s-alice", "198.51.100.2", *now); err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(ctx, uc, false, "mallory", "", "", *now); !errors.Is(err, errNotFound) {
		t.Errorf("second decision: %v", err)
	}
	*now = now.Add(20 * time.Second)
	res, g, err := s.Poll(ctx, dc, "cli")
	if res != PollApproved || err != nil || g.UserID != "alice" {
		t.Fatalf("approved poll: %v %+v %v", res, g, err)
	}

	// Two pollers race to consume: exactly one gets the device.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var devices []*Device
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := s.Consume(ctx, dc, NewDevice{Name: "laptop", RefreshToken: "hkrt_first" + string(rune('a'+i)), RefreshExp: now.Add(time.Hour)})
			if err == nil {
				mu.Lock()
				devices = append(devices, d)
				mu.Unlock()
			} else if !errors.Is(err, errNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if len(devices) != 1 || devices[0].UserID != "alice" || devices[0].CreatedIP != "203.0.113.7" {
		t.Fatalf("consume: %+v", devices)
	}
	*now = now.Add(20 * time.Second)
	if res, _, _ := s.Poll(ctx, dc, "cli"); res != PollUnknown {
		t.Errorf("poll after consume: %v", res)
	}
	if list, _ := s.UserDevices(ctx, "alice"); len(list) != 1 || list[0].ID != devices[0].ID {
		t.Errorf("user devices: %+v", list)
	}

	// Denied and expired grants.
	dc2, uc2 := newGrant(t, s)
	_ = s.Decide(ctx, uc2, false, "alice", "", "", *now)
	if res, _, _ := s.Poll(ctx, dc2, "cli"); res != PollDenied {
		t.Errorf("denied: %v", res)
	}
	dc3, uc3 := newGrant(t, s)
	*now = now.Add(11 * time.Minute)
	if res, _, _ := s.Poll(ctx, dc3, "cli"); res != PollExpired {
		t.Errorf("expired: %v", res)
	}
	if _, err := s.PendingGrant(ctx, uc3); !errors.Is(err, errNotFound) {
		t.Errorf("expired grant still pending: %v", err)
	}
	if err := s.Decide(ctx, uc3, true, "alice", "", "", *now); !errors.Is(err, errNotFound) {
		t.Errorf("approving an expired grant: %v", err)
	}
}

// approvedDevice runs a grant through to a device holding refresh token rt.
func approvedDevice(t *testing.T, s *DeviceStore, user, rt string) *Device {
	t.Helper()
	ctx := context.Background()
	dc, uc := newGrant(t, s)
	if err := s.Decide(ctx, uc, true, user, "", "", s.now()); err != nil {
		t.Fatal(err)
	}
	d, err := s.Consume(ctx, dc, NewDevice{Name: "laptop", RefreshToken: rt, RefreshExp: s.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRefreshRotation(t *testing.T) {
	s, now := testDeviceStore(t)
	ctx := context.Background()
	d := approvedDevice(t, s, "alice", "rt0")
	grace := 30 * time.Second

	res, got, err := s.Refresh(ctx, "rt0", "rt1", now.Add(time.Hour), "198.51.100.9", grace)
	if res != RefreshRotated || err != nil || got.ID != d.ID || got.LastUsedIP != "198.51.100.9" {
		t.Fatalf("rotate: %v %+v %v", res, got, err)
	}
	// A concurrent refresh with the old token inside the grace window gets a new token, and
	// the one handed out a moment ago stops working.
	*now = now.Add(10 * time.Second)
	if res, _, _ := s.Refresh(ctx, "rt0", "rt2", now.Add(time.Hour), "", grace); res != RefreshRotated {
		t.Fatalf("grace replay: %v", res)
	}
	*now = now.Add(time.Second)
	if res, _, _ := s.Refresh(ctx, "rt2", "rt3", now.Add(time.Hour), "", grace); res != RefreshRotated {
		t.Fatalf("newest token: %v", res)
	}
	// rt0 again, well after the grace window: theft. The device is revoked.
	*now = now.Add(time.Minute)
	if res, _, _ := s.Refresh(ctx, "rt0", "rt4", now.Add(time.Hour), "", grace); res != RefreshReused {
		t.Fatalf("late replay: %v", res)
	}
	if res, _, _ := s.Refresh(ctx, "rt3", "rt5", now.Add(time.Hour), "", grace); res != RefreshInvalid {
		t.Errorf("token of a revoked device: %v", res)
	}
	if dev, _ := s.Device(ctx, d.ID); dev.RevokedAt == nil || dev.RevokedBy != "reuse" {
		t.Errorf("device after reuse: %+v", dev)
	}
	if ok, _ := s.DeviceActive(ctx, d.ID); ok {
		t.Error("revoked device is active")
	}

	// Idle expiry.
	d2 := approvedDevice(t, s, "alice", "idle0")
	*now = now.Add(2 * time.Hour)
	if res, _, _ := s.Refresh(ctx, "idle0", "idle1", now.Add(time.Hour), "", grace); res != RefreshInvalid {
		t.Errorf("idle-expired token: %v", res)
	}
	if ok, _ := s.DeviceActive(ctx, d2.ID); !ok {
		t.Error("an idle-expired token shouldn't revoke the device")
	}
	if res, _, _ := s.Refresh(ctx, "nope", "x", now.Add(time.Hour), "", grace); res != RefreshInvalid {
		t.Errorf("unknown token: %v", res)
	}
}

func TestRefreshParallel(t *testing.T) {
	s, now := testDeviceStore(t)
	ctx := context.Background()
	d := approvedDevice(t, s, "alice", "p0")
	var wg sync.WaitGroup
	results := make([]RefreshResult, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, _, err := s.Refresh(ctx, "p0", "p1-"+string(rune('a'+i)), now.Add(time.Hour), "", 30*time.Second)
			if err != nil {
				t.Error(err)
			}
			results[i] = res
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r != RefreshRotated {
			t.Errorf("parallel refresh %d: %v", i, r)
		}
	}
	if ok, _ := s.DeviceActive(ctx, d.ID); !ok {
		t.Error("parallel refreshes revoked the device")
	}
	var current int
	_ = s.pool.QueryRow(ctx, "SELECT count(*) FROM hankoid.oidc_refresh_tokens WHERE device_id = $1 AND rotated_at IS NULL", d.ID).Scan(&current)
	if current != 1 {
		t.Errorf("device has %d current tokens, want 1", current)
	}
}

func TestRevocationsAndTickets(t *testing.T) {
	s, now := testDeviceStore(t)
	ctx := context.Background()
	start := *now
	a := approvedDevice(t, s, "alice", "a0")
	b := approvedDevice(t, s, "alice", "b0")
	c := approvedDevice(t, s, "bob", "c0")

	if ok, _ := s.RevokeDevice(ctx, a.ID, "bob", "user"); ok {
		t.Error("bob revoked alice's device")
	}
	*now = now.Add(time.Second)
	if ok, err := s.RevokeDevice(ctx, a.ID, "alice", "user"); !ok || err != nil {
		t.Errorf("revoke own device: %v %v", ok, err)
	}
	if ok, _ := s.RevokeDevice(ctx, a.ID, "alice", "user"); ok {
		t.Error("revoking twice reported a revocation")
	}
	*now = now.Add(time.Second)
	ids, err := s.RevokeUserDevices(ctx, "alice", "admin")
	if err != nil || len(ids) != 1 || ids[0] != b.ID {
		t.Errorf("revoke all: %v %v", ids, err)
	}
	if res, _, _ := s.Refresh(ctx, "b0", "b1", now.Add(time.Hour), "", time.Second); res != RefreshInvalid {
		t.Errorf("refresh after revoke: %v", res)
	}
	if list, _ := s.UserDevices(ctx, "alice"); len(list) != 0 {
		t.Errorf("revoked devices listed: %+v", list)
	}
	revs, cursor, err := s.RevokedSince(ctx, start, 100)
	if err != nil || len(revs) != 2 || revs[0].DeviceID != a.ID || revs[1].Reason != "admin" || !cursor.Equal(*now) {
		t.Errorf("feed: %+v %v %v", revs, cursor, err)
	}
	if id, _ := s.RevokeByRefreshToken(ctx, "c0", "other-client"); id != "" {
		t.Error("revoked through another client")
	}
	if id, _ := s.RevokeByRefreshToken(ctx, "c0", "cli"); id != c.ID {
		t.Errorf("RFC 7009 revoke: %q", id)
	}

	tk, err := s.CreateTicket(ctx, Ticket{Resource: "wss://fs.test/9p", UserID: "alice", ClientID: "cli", Username: "alice"}, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RedeemTicket(ctx, tk, "wss://other.test/9p"); err == nil {
		t.Error("ticket worked for another resource")
	}
	if got, err := s.RedeemTicket(ctx, tk, "wss://fs.test/9p"); err != nil || got.UserID != "alice" || got.Username != "alice" {
		t.Errorf("redeem: %+v %v", got, err)
	}
	if _, err := s.RedeemTicket(ctx, tk, "wss://fs.test/9p"); err == nil {
		t.Error("ticket redeemed twice")
	}
	tk2, _ := s.CreateTicket(ctx, Ticket{Resource: "r", UserID: "alice", DeviceID: c.ID, ClientID: "cli"}, 30*time.Second)
	*now = now.Add(time.Minute)
	if _, err := s.RedeemTicket(ctx, tk2, "r"); err == nil {
		t.Error("expired ticket redeemed")
	}

	*now = now.Add(31 * 24 * time.Hour)
	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = s.pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM hankoid.oidc_devices WHERE revoked_at IS NOT NULL) + (SELECT count(*) FROM hankoid.oidc_device_grants) + (SELECT count(*) FROM hankoid.gateway_tickets)").Scan(&n)
	if n != 0 {
		t.Errorf("%d expired rows left", n)
	}
}
