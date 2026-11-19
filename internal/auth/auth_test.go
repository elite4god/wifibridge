package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestAuthManager(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wifibridge-auth-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mgr, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}

	// Initial check: setup not complete
	if mgr.IsSetupComplete() {
		t.Errorf("expected setup to be incomplete initially")
	}

	// Attempt short password
	err = mgr.CreateAdmin("admin", "short")
	if err == nil {
		t.Errorf("expected error for short password, got nil")
	}

	// Create valid admin
	err = mgr.CreateAdmin("admin", "correct-horse-battery")
	if err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	if !mgr.IsSetupComplete() {
		t.Errorf("expected setup to be complete")
	}

	// Test authentication
	if !mgr.Authenticate("admin", "correct-horse-battery") {
		t.Errorf("expected valid credentials to authenticate successfully")
	}
	if mgr.Authenticate("admin", "wrong-password") {
		t.Errorf("expected invalid password to fail authentication")
	}
	if mgr.Authenticate("unknown", "correct-horse-battery") {
		t.Errorf("expected invalid username to fail authentication")
	}

	// Test Session Cookie Issuance and Validation
	w := httptest.NewRecorder()
	mgr.CreateSession(w)

	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie to be set")
	}

	req := httptest.NewRequest("GET", "/dashboard", nil)
	req.AddCookie(cookies[0])

	if !mgr.ValidateSession(req) {
		t.Errorf("expected session cookie to be valid")
	}

	// Test Cookie Tampering
	tamperedCookie := &http.Cookie{
		Name:  cookies[0].Name,
		Value: cookies[0].Value + "bad",
	}
	reqBad := httptest.NewRequest("GET", "/dashboard", nil)
	reqBad.AddCookie(tamperedCookie)
	if mgr.ValidateSession(reqBad) {
		t.Errorf("expected tampered session cookie to fail validation")
	}

	// Test Clear Session
	wClear := httptest.NewRecorder()
	mgr.ClearSession(wClear)
	clearCookies := wClear.Result().Cookies()
	if len(clearCookies) == 0 || clearCookies[0].MaxAge != -1 {
		t.Errorf("expected session cookie to be cleared")
	}
}

func TestRequireAuthMiddleware(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wifibridge-auth-mw-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mgr, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to init auth manager: %v", err)
	}

	targetReached := false
	handler := mgr.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReached = true
		w.WriteHeader(http.StatusOK)
	}))

	// Case 1: Before setup -> should redirect to /setup
	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if targetReached {
		t.Errorf("unauthenticated request before setup should not reach target")
	}
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/setup" {
		t.Errorf("expected redirect to /setup, got status %d, location %s", w.Code, w.Header().Get("Location"))
	}

	// Set up admin
	_ = mgr.CreateAdmin("admin", "password123")

	// Case 2: After setup, no session -> should redirect to /login
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login" {
		t.Errorf("expected redirect to /login, got status %d, location %s", w.Code, w.Header().Get("Location"))
	}

	// Case 3: After setup, valid session -> should allow access
	wSess := httptest.NewRecorder()
	mgr.CreateSession(wSess)
	cookie := wSess.Result().Cookies()[0]

	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !targetReached {
		t.Errorf("authenticated request should reach target handler")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	// Case 4: Static assets allowed without session
	reqStatic := httptest.NewRequest("GET", "/static/css/bootstrap.min.css", nil)
	targetReached = false
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, reqStatic)
	if !targetReached {
		t.Errorf("static asset should bypass auth")
	}
}
