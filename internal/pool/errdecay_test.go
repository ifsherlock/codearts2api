package pool

import (
	"testing"
	"time"

	"codearts2api/internal/auth"
)

// newDecayPool 构造一个单账号池，供 errCount 衰减相关测试复用。
func newDecayPool(t *testing.T) (*Pool, *Account) {
	t.Helper()
	a := auth.New("u1", "user", "domain", "token", "ak", "sk",
		time.Now().Add(time.Hour).Format(time.RFC3339), "", "verifier")
	p, err := New([]*auth.Auth{a}, Config{MaxConcurrent: 1, ErrThreshold: 3}, "")
	if err != nil {
		t.Fatal(err)
	}
	acct := p.Get("u1")
	if acct == nil {
		t.Fatal("account not found in pool")
	}
	return p, acct
}

// TestNoteErrorReachesThresholdAndCools 守住原有行为：连续记错到阈值仍要冷却。
func TestNoteErrorReachesThresholdAndCools(t *testing.T) {
	p, acct := newDecayPool(t)
	for i := 0; i < 3; i++ {
		p.NoteError("u1", 3, 10*time.Minute)
	}

	acct.mu.Lock()
	count, coolUntil, lastErr := acct.errCount, acct.coolUntil, acct.lastErr
	acct.mu.Unlock()

	if count != 3 {
		t.Fatalf("errCount=%d, want 3", count)
	}
	if !time.Now().Before(coolUntil) {
		t.Fatal("account should be cooling after reaching the threshold")
	}
	if lastErr != errConsecutiveMsg {
		t.Fatalf("lastErr=%q, want %q", lastErr, errConsecutiveMsg)
	}
}

// TestErrCountDecaysAfterWindow 是本次修复的核心：超过衰减窗口未再出错，
// 计数与 lastErr 都要自动归零，否则长期不接流量的账号会永久挂着
// "consecutive errors"（线上实测：3 次瞬时排队失败钉了 26 小时）。
func TestErrCountDecaysAfterWindow(t *testing.T) {
	p, acct := newDecayPool(t)
	p.NoteError("u1", 3, 10*time.Minute)
	p.NoteError("u1", 3, 10*time.Minute)

	// 把记账时刻推回到衰减窗口之外，模拟「很久没再出错」。
	acct.mu.Lock()
	acct.errLastAt = time.Now().Add(-errDecay - time.Minute)
	acct.mu.Unlock()

	if got := p.List()[0]["err_count"]; got != 0 {
		t.Fatalf("err_count=%v, want 0 after decay window", got)
	}

	acct.mu.Lock()
	count, lastErr := acct.errCount, acct.lastErr
	acct.mu.Unlock()
	if count != 0 {
		t.Fatalf("errCount=%d, want 0", count)
	}
	if lastErr != "" {
		t.Fatalf("lastErr=%q, want empty after decay", lastErr)
	}
}

// TestErrCountResetsAfterCooldownExpiry 冷却一过，那次故障的记账就该失效。
func TestErrCountResetsAfterCooldownExpiry(t *testing.T) {
	p, acct := newDecayPool(t)
	for i := 0; i < 3; i++ {
		p.NoteError("u1", 3, 10*time.Minute)
	}

	// 冷却已过期（errLastAt 仍在窗口内，验证冷却这条独立生效）。
	acct.mu.Lock()
	acct.coolUntil = time.Now().Add(-time.Minute)
	acct.mu.Unlock()

	if got := p.List()[0]["err_count"]; got != 0 {
		t.Fatalf("err_count=%v, want 0 after cooldown expiry", got)
	}
}

// TestNoteErrorDoesNotStackAcrossDecay 衰减后重新记错应从 1 开始，
// 不能把窗口外的旧计数继续累加（否则偶发故障会攒成永久冷却）。
func TestNoteErrorDoesNotStackAcrossDecay(t *testing.T) {
	p, acct := newDecayPool(t)
	p.NoteError("u1", 3, 10*time.Minute)
	p.NoteError("u1", 3, 10*time.Minute)

	acct.mu.Lock()
	acct.errLastAt = time.Now().Add(-errDecay - time.Minute)
	acct.mu.Unlock()

	p.NoteError("u1", 3, 10*time.Minute)

	acct.mu.Lock()
	count, cooling := acct.errCount, time.Now().Before(acct.coolUntil)
	acct.mu.Unlock()

	if count != 1 {
		t.Fatalf("errCount=%d, want 1 (counter restarts after decay)", count)
	}
	if cooling {
		t.Fatal("single error after decay must not cool the account")
	}
}

// TestNoteSuccessClearsErrState 成功一次仍应把计数与残留文案清干净。
func TestNoteSuccessClearsErrState(t *testing.T) {
	p, acct := newDecayPool(t)
	for i := 0; i < 3; i++ {
		p.NoteError("u1", 3, 10*time.Minute)
	}
	p.NoteSuccess("u1")

	acct.mu.Lock()
	count, lastErr, errLastAt := acct.errCount, acct.lastErr, acct.errLastAt
	acct.mu.Unlock()

	if count != 0 {
		t.Fatalf("errCount=%d, want 0", count)
	}
	if lastErr != "" {
		t.Fatalf("lastErr=%q, want empty", lastErr)
	}
	if !errLastAt.IsZero() {
		t.Fatalf("errLastAt=%v, want zero", errLastAt)
	}
}

// TestNoteSuccessKeepsDisabledReason 禁用原因不能被成功路径顺手抹掉。
func TestNoteSuccessKeepsDisabledReason(t *testing.T) {
	p, acct := newDecayPool(t)
	p.Disable("u1", "401 invalid token")
	p.NoteSuccess("u1")

	acct.mu.Lock()
	reason, lastErr := acct.disabledReason, acct.lastErr
	acct.mu.Unlock()

	if reason != "401 invalid token" {
		t.Fatalf("disabledReason=%q, want preserved", reason)
	}
	if lastErr != "401 invalid token" {
		t.Fatalf("lastErr=%q, want preserved for disabled account", lastErr)
	}
}

// TestErrLastAtSurvivesStateRoundTrip 衰减时间戳必须落盘，否则重启后
// 会退化成「errCount 非零但 errLastAt 为零」，永不衰减。
func TestErrLastAtSurvivesStateRoundTrip(t *testing.T) {
	state := t.TempDir() + "/state.json"
	a := auth.New("u1", "user", "domain", "token", "ak", "sk",
		time.Now().Add(time.Hour).Format(time.RFC3339), "", "verifier")
	p, err := New([]*auth.Auth{a}, Config{MaxConcurrent: 1, ErrThreshold: 3}, state)
	if err != nil {
		t.Fatal(err)
	}
	p.NoteError("u1", 3, 10*time.Minute)

	acct := p.Get("u1")
	acct.mu.Lock()
	want := acct.errLastAt
	acct.mu.Unlock()
	if want.IsZero() {
		t.Fatal("errLastAt not recorded")
	}

	// 重新从磁盘加载。
	p2, err := New([]*auth.Auth{a}, Config{MaxConcurrent: 1, ErrThreshold: 3}, state)
	if err != nil {
		t.Fatal(err)
	}
	acct2 := p2.Get("u1")
	acct2.mu.Lock()
	got := acct2.errLastAt
	acct2.mu.Unlock()

	if !got.Equal(want) {
		t.Fatalf("errLastAt=%v, want %v", got, want)
	}
}
