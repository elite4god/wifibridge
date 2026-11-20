package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"wifibridge/internal/auth"
	"wifibridge/internal/config"
	"wifibridge/internal/network"
)

func setupTestServer(t *testing.T) (*Server, string, string) {
	stateDir, err := os.MkdirTemp("", "wb-web-state-*")
	if err != nil {
		t.Fatalf("failed to create state dir: %v", err)
	}

	sysRoot, err := os.MkdirTemp("", "wb-web-sys-*")
	if err != nil {
		t.Fatalf("failed to create sys root: %v", err)
	}

	cfgMgr, err := config.NewManager(stateDir)
	if err != nil {
		t.Fatalf("failed to create cfg mgr: %v", err)
	}

	authMgr, err := auth.NewManager(stateDir)
	if err != nil {
		t.Fatalf("failed to create auth mgr: %v", err)
	}

	mockSys := &network.MockSystemManager{
		UplinkSuccess: true,
		AssignedIP:    "192.168.1.100",
	}

	applier := network.NewApplier(cfgMgr, mockSys, sysRoot)

	srv, err := NewServer(cfgMgr, authMgr, applier, mockSys, sysRoot, true)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return srv, stateDir, sysRoot
}

func TestFirstBootSetupAndAuthFlow(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	// 1. Unauthenticated root request before setup -> Redirect to /setup
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusFound || w.Header().Get("Location") != "/setup" {
		t.Fatalf("expected redirect to /setup, got status %d, location %s", w.Code, w.Header().Get("Location"))
	}

	// 2. Perform Setup POST
	form := url.Values{
		"username":         {"admin"},
		"password":         {"super-secret-password"},
		"confirm_password": {"super-secret-password"},
	}
	reqSetup := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	reqSetup.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wSetup := httptest.NewRecorder()
	srv.ServeHTTP(wSetup, reqSetup)

	if wSetup.Code != http.StatusSeeOther {
		t.Fatalf("expected setup redirect 303, got %d", wSetup.Code)
	}

	cookies := wSetup.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected session cookie after setup")
	}
	sessionCookie := cookies[0]

	// 3. Access Dashboard with session cookie
	reqDash := httptest.NewRequest("GET", "/dashboard", nil)
	reqDash.AddCookie(sessionCookie)
	wDash := httptest.NewRecorder()
	srv.ServeHTTP(wDash, reqDash)

	if wDash.Code != http.StatusOK {
		t.Fatalf("expected dashboard OK 200, got %d", wDash.Code)
	}
	body := wDash.Body.String()
	if !strings.Contains(body, "WifiBridge") || !strings.Contains(body, "Upstream WAN") {
		t.Errorf("dashboard response missing expected content:\n%s", body)
	}
	if !strings.Contains(body, "192.168.1.100") {
		t.Errorf("expected dashboard to show public interface IP 192.168.1.100, got:\n%s", body)
	}
	if !strings.Contains(body, "br0") {
		t.Errorf("expected dashboard to show bridge br0, got:\n%s", body)
	}
}

func TestStagingAndPushFlow(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	// Create admin & session
	_ = srv.authMgr.CreateAdmin("admin", "password123")
	wAuth := httptest.NewRecorder()
	srv.authMgr.CreateSession(wAuth)
	sessionCookie := wAuth.Result().Cookies()[0]

	// Initial Dashboard check: no staged banner
	reqDash := httptest.NewRequest("GET", "/dashboard", nil)
	reqDash.AddCookie(sessionCookie)
	wDash := httptest.NewRecorder()
	srv.ServeHTTP(wDash, reqDash)
	if strings.Contains(wDash.Body.String(), "Pending Staged Changes") {
		t.Errorf("expected no pending staged changes initially")
	}

	// Stage an AP Change: SSID -> "TravelRouter5G"
	formAP := url.Values{
		"ssid":       {"TravelRouter5G"},
		"security":   {"wpa2-psk"},
		"passphrase": {"NewPassword123"},
		"band":       {"5GHz"},
		"channel":    {"36"},
	}
	reqAP := httptest.NewRequest("POST", "/ap", strings.NewReader(formAP.Encode()))
	reqAP.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAP.AddCookie(sessionCookie)
	wAP := httptest.NewRecorder()
	srv.ServeHTTP(wAP, reqAP)

	if wAP.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after staging AP change, got %d", wAP.Code)
	}

	// Verify staged banner appears on Dashboard
	wDash2 := httptest.NewRecorder()
	srv.ServeHTTP(wDash2, reqDash)
	body2 := wDash2.Body.String()
	if !strings.Contains(body2, "Pending Staged Changes") || !strings.Contains(body2, "TravelRouter5G") {
		t.Errorf("expected staged changes banner on dashboard after staging change")
	}

	// Discard Changes
	reqDiscard := httptest.NewRequest("POST", "/config/discard", nil)
	reqDiscard.AddCookie(sessionCookie)
	wDiscard := httptest.NewRecorder()
	srv.ServeHTTP(wDiscard, reqDiscard)

	if wDiscard.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after discard, got %d", wDiscard.Code)
	}

	// Verify banner is gone
	wDash3 := httptest.NewRecorder()
	srv.ServeHTTP(wDash3, reqDash)
	if strings.Contains(wDash3.Body.String(), "Pending Staged Changes") {
		t.Errorf("expected staged banner to be gone after discard")
	}

	// Stage AP change again
	wAP2 := httptest.NewRecorder()
	srv.ServeHTTP(wAP2, reqAP)

	// Push Changes to Live System
	reqPush := httptest.NewRequest("POST", "/config/push", nil)
	reqPush.AddCookie(sessionCookie)
	wPush := httptest.NewRecorder()
	srv.ServeHTTP(wPush, reqPush)

	if wPush.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after push, got %d", wPush.Code)
	}

	// Verify live system has been updated
	liveCfg := srv.cfgMgr.GetLive()
	if liveCfg.AP.SSID != "TravelRouter5G" {
		t.Errorf("expected live AP SSID to be TravelRouter5G, got %s", liveCfg.AP.SSID)
	}
}

func TestWireGuardKeygenEndpoint(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	_ = srv.authMgr.CreateAdmin("admin", "password123")
	wAuth := httptest.NewRecorder()
	srv.authMgr.CreateSession(wAuth)
	sessionCookie := wAuth.Result().Cookies()[0]

	reqKeygen := httptest.NewRequest("POST", "/vpn/wireguard/keygen", nil)
	reqKeygen.AddCookie(sessionCookie)
	wKeygen := httptest.NewRecorder()
	srv.ServeHTTP(wKeygen, reqKeygen)

	if wKeygen.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from keygen endpoint, got %d", wKeygen.Code)
	}
	body := wKeygen.Body.String()
	if !strings.Contains(body, "Generated fresh Curve25519 keypair") || !strings.Contains(body, "private_key") {
		t.Errorf("unexpected keygen response:\n%s", body)
	}
}

func TestWiFiScanEndpoint(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	_ = srv.authMgr.CreateAdmin("admin", "password123")
	wAuth := httptest.NewRecorder()
	srv.authMgr.CreateSession(wAuth)
	sessionCookie := wAuth.Result().Cookies()[0]

	reqScan := httptest.NewRequest("GET", "/wan/scan", nil)
	reqScan.AddCookie(sessionCookie)
	wScan := httptest.NewRecorder()
	srv.ServeHTTP(wScan, reqScan)

	if wScan.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from scan endpoint, got %d", wScan.Code)
	}
	body := wScan.Body.String()
	if !strings.Contains(body, "Hotel-Guest-WiFi") {
		t.Errorf("expected scanned network in scan output:\n%s", body)
	}
}

func TestStaticAssetsAndFontResolution(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	// 1. Verify bootstrap-icons CSS contains relative ../fonts/ path
	reqCSS := httptest.NewRequest("GET", "/static/css/bootstrap-icons.min.css", nil)
	wCSS := httptest.NewRecorder()
	srv.ServeHTTP(wCSS, reqCSS)
	if wCSS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for bootstrap-icons.min.css, got %d", wCSS.Code)
	}
	cssBody := wCSS.Body.String()
	if !strings.Contains(cssBody, `url("../fonts/bootstrap-icons.woff2`) {
		t.Errorf("expected bootstrap-icons.min.css to reference ../fonts/bootstrap-icons.woff2, got:\n%s", cssBody[:200])
	}

	// 2. Verify direct font request returns 200 OK with correct MIME type
	for _, fontPath := range []string{"/static/fonts/bootstrap-icons.woff2", "/static/fonts/bootstrap-icons.woff"} {
		reqFont := httptest.NewRequest("GET", fontPath, nil)
		wFont := httptest.NewRecorder()
		srv.ServeHTTP(wFont, reqFont)
		if wFont.Code != http.StatusOK {
			t.Errorf("expected 200 OK for %s, got %d", fontPath, wFont.Code)
		}
		if wFont.Body.Len() == 0 {
			t.Errorf("expected non-empty body for %s", fontPath)
		}
	}

	// 3. Verify aliased css/fonts/ path returns 200 OK for backward compatibility
	reqAliased := httptest.NewRequest("GET", "/static/css/fonts/bootstrap-icons.woff2", nil)
	wAliased := httptest.NewRecorder()
	srv.ServeHTTP(wAliased, reqAliased)
	if wAliased.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /static/css/fonts/bootstrap-icons.woff2, got %d", wAliased.Code)
	}
}

func TestInterfaceSelectionAndSideBySideDiff(t *testing.T) {
	srv, stateDir, sysRoot := setupTestServer(t)
	defer os.RemoveAll(stateDir)
	defer os.RemoveAll(sysRoot)

	_ = srv.authMgr.CreateAdmin("admin", "password123")
	wAuth := httptest.NewRecorder()
	srv.authMgr.CreateSession(wAuth)
	sessionCookie := wAuth.Result().Cookies()[0]

	// 1. Verify GET /wan includes WAN Physical Interface dropdown
	reqWANGet := httptest.NewRequest("GET", "/wan", nil)
	reqWANGet.AddCookie(sessionCookie)
	wWANGet := httptest.NewRecorder()
	srv.ServeHTTP(wWANGet, reqWANGet)
	if wWANGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /wan, got %d", wWANGet.Code)
	}
	wanBody := wWANGet.Body.String()
	if !strings.Contains(wanBody, `name="wan_interface"`) {
		t.Errorf("expected /wan to contain wan_interface select field")
	}

	// 2. Verify GET /ap includes AP Physical Interface dropdown
	reqAPGet := httptest.NewRequest("GET", "/ap", nil)
	reqAPGet.AddCookie(sessionCookie)
	wAPGet := httptest.NewRecorder()
	srv.ServeHTTP(wAPGet, reqAPGet)
	if wAPGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /ap, got %d", wAPGet.Code)
	}
	apBody := wAPGet.Body.String()
	if !strings.Contains(apBody, `name="ap_interface"`) {
		t.Errorf("expected /ap to contain ap_interface select field")
	}

	// 3. Verify GET /lan includes LAN Bridge Interface field
	reqLANGet := httptest.NewRequest("GET", "/lan", nil)
	reqLANGet.AddCookie(sessionCookie)
	wLANGet := httptest.NewRecorder()
	srv.ServeHTTP(wLANGet, reqLANGet)
	if wLANGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /lan, got %d", wLANGet.Code)
	}
	lanBody := wLANGet.Body.String()
	if !strings.Contains(lanBody, `name="lan_interface"`) {
		t.Errorf("expected /lan to contain lan_interface field")
	}

	// 4. Stage custom WAN interface: "enp3s0"
	formWAN := url.Values{
		"mode":          {"ethernet"},
		"wan_interface": {"enp3s0"},
	}
	reqWANPost := httptest.NewRequest("POST", "/wan", strings.NewReader(formWAN.Encode()))
	reqWANPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqWANPost.AddCookie(sessionCookie)
	wWANPost := httptest.NewRecorder()
	srv.ServeHTTP(wWANPost, reqWANPost)
	if wWANPost.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after staging WAN, got %d", wWANPost.Code)
	}

	// 5. Stage custom AP interface: "wlan2"
	formAP := url.Values{
		"ap_interface": {"wlan2"},
		"ssid":         {"CustomAP"},
		"security":     {"open"},
		"band":         {"2.4GHz"},
		"channel":      {"6"},
	}
	reqAPPost := httptest.NewRequest("POST", "/ap", strings.NewReader(formAP.Encode()))
	reqAPPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAPPost.AddCookie(sessionCookie)
	wAPPost := httptest.NewRecorder()
	srv.ServeHTTP(wAPPost, reqAPPost)
	if wAPPost.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after staging AP, got %d", wAPPost.Code)
	}

	// 6. Stage custom LAN interface: "br1"
	formLAN := url.Values{
		"lan_interface": {"br1"},
		"gateway_ip":    {"10.99.0.1"},
		"subnet":        {"10.99.0.0/24"},
		"pool_offset":   {"100"},
		"pool_size":     {"150"},
		"lease_time":    {"86400"},
	}
	reqLANPost := httptest.NewRequest("POST", "/lan", strings.NewReader(formLAN.Encode()))
	reqLANPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqLANPost.AddCookie(sessionCookie)
	wLANPost := httptest.NewRecorder()
	srv.ServeHTTP(wLANPost, reqLANPost)
	if wLANPost.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after staging LAN, got %d", wLANPost.Code)
	}

	// 7. Verify Side-by-Side Diff modal on /dashboard
	reqDash := httptest.NewRequest("GET", "/dashboard", nil)
	reqDash.AddCookie(sessionCookie)
	wDash := httptest.NewRecorder()
	srv.ServeHTTP(wDash, reqDash)
	dashBody := wDash.Body.String()

	// Verify Side-by-Side Table Headers
	if !strings.Contains(dashBody, "Current Active Config") || !strings.Contains(dashBody, "Staged Config") {
		t.Errorf("expected side-by-side diff table headers 'Current Active Config' and 'Staged Config' in dashboard HTML")
	}

	// Verify diff values are rendered
	if !strings.Contains(dashBody, "enp3s0") || !strings.Contains(dashBody, "wlan2") || !strings.Contains(dashBody, "br1") {
		t.Errorf("expected staged interface values enp3s0, wlan2, br1 in diff modal, got:\n%s", dashBody)
	}
	if !strings.Contains(dashBody, "wlan1") || !strings.Contains(dashBody, "wlan0") || !strings.Contains(dashBody, "br0") {
		t.Errorf("expected active interface values wan1, wlan0, br0 in diff modal, got:\n%s", dashBody)
	}

	// 8. Commit and Push staged changes
	reqPush := httptest.NewRequest("POST", "/config/push", nil)
	reqPush.AddCookie(sessionCookie)
	wPush := httptest.NewRecorder()
	srv.ServeHTTP(wPush, reqPush)
	if wPush.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect after push, got %d", wPush.Code)
	}

	// 9. Verify LiveConfig has updated interfaces
	liveCfg := srv.cfgMgr.GetLive()
	if liveCfg.WAN.Interface != "enp3s0" {
		t.Errorf("expected live WAN Interface to be enp3s0, got %s", liveCfg.WAN.Interface)
	}
	if liveCfg.AP.Interface != "wlan2" {
		t.Errorf("expected live AP Interface to be wlan2, got %s", liveCfg.AP.Interface)
	}
	if liveCfg.LAN.Interface != "br1" {
		t.Errorf("expected live LAN Interface to be br1, got %s", liveCfg.LAN.Interface)
	}
}
