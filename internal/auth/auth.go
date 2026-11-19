package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "wb_session"
	sessionDuration   = 24 * time.Hour
)

// AuthData represents the persisted credentials and signing secret.
type AuthData struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	SigningKey   string `json:"signing_key"`
}

// Manager handles user authentication, session cookies, and setup state.
type Manager struct {
	mu       sync.RWMutex
	stateDir string
	authPath string
	data     *AuthData
}

// NewManager initializes the authentication manager.
func NewManager(stateDir string) (*Manager, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create auth directory: %w", err)
	}

	m := &Manager{
		stateDir: stateDir,
		authPath: filepath.Join(stateDir, "auth.json"),
	}

	if err := m.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load auth state: %w", err)
	}

	return m, nil
}

func (m *Manager) load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.authPath)
	if err != nil {
		return err
	}

	var auth AuthData
	if err := json.Unmarshal(data, &auth); err != nil {
		return err
	}
	m.data = &auth
	return nil
}

// IsSetupComplete returns true if administrator credentials have been created.
func (m *Manager) IsSetupComplete() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.data != nil && m.data.Username != "" && m.data.PasswordHash != ""
}

// CreateAdmin initializes administrator credentials and generates a signing key.
func (m *Manager) CreateAdmin(username, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username cannot be empty")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	data := &AuthData{
		Username:     username,
		PasswordHash: string(hash),
		SigningKey:   hex.EncodeToString(keyBytes),
	}

	fileData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	tmpPath := m.authPath + ".tmp"
	if err := os.WriteFile(tmpPath, fileData, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, m.authPath); err != nil {
		return err
	}

	m.data = data
	return nil
}

// Authenticate checks the provided username and password against the stored bcrypt hash.
func (m *Manager) Authenticate(username, password string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data == nil {
		return false
	}
	if m.data.Username != strings.TrimSpace(username) {
		return false
	}

	return bcrypt.CompareHashAndPassword([]byte(m.data.PasswordHash), []byte(password)) == nil
}

// CreateSession sets a signed session cookie on the HTTP response.
func (m *Manager) CreateSession(w http.ResponseWriter) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data == nil || m.data.SigningKey == "" {
		return
	}

	expires := time.Now().Add(sessionDuration).Unix()
	payload := fmt.Sprintf("%s:%d", m.data.Username, expires)
	sig := m.sign(payload)
	val := fmt.Sprintf("%s:%s", payload, sig)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    val,
		Path:     "/",
		Expires:  time.Now().Add(sessionDuration),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ValidateSession checks if the request contains a valid, non-expired signed session cookie.
func (m *Manager) ValidateSession(r *http.Request) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.data == nil || m.data.SigningKey == "" {
		return false
	}

	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 3 {
		return false
	}

	username := parts[0]
	expiresStr := parts[1]
	sig := parts[2]

	if username != m.data.Username {
		return false
	}

	exp, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}

	payload := fmt.Sprintf("%s:%s", username, expiresStr)
	expectedSig := m.sign(payload)

	return hmac.Equal([]byte(sig), []byte(expectedSig))
}

// ClearSession clears the session cookie.
func (m *Manager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, []byte(m.data.SigningKey))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// RequireAuth middleware protects routes, redirecting to /setup or /login.
func (m *Manager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Allow static assets, setup endpoints, and login/logout endpoints
		if strings.HasPrefix(path, "/static/") ||
			path == "/setup" ||
			path == "/login" {
			next.ServeHTTP(w, r)
			return
		}

		if !m.IsSetupComplete() {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}

		if !m.ValidateSession(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
