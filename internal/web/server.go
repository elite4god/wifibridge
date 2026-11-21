package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"strings"
	"wifibridge/internal/auth"
	"wifibridge/internal/config"
	"wifibridge/internal/network"
)

// Server encapsulates the HTTP router, templates, and application services.
type Server struct {
	cfgMgr    *config.Manager
	authMgr   *auth.Manager
	applier   *network.Applier
	sysMgr    network.SystemManager
	sysRoot   string
	mock      bool
	templates map[string]*template.Template
	mux       *http.ServeMux
}

// NewServer initializes templates and configures the HTTP routes.
func NewServer(cfgMgr *config.Manager, authMgr *auth.Manager, applier *network.Applier, sysMgr network.SystemManager, sysRoot string, mock bool) (*Server, error) {
	s := &Server{
		cfgMgr:    cfgMgr,
		authMgr:   authMgr,
		applier:   applier,
		sysMgr:    sysMgr,
		sysRoot:   sysRoot,
		mock:      mock,
		templates: make(map[string]*template.Template),
		mux:       http.NewServeMux(),
	}

	if err := s.initTemplates(); err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	s.setupRoutes()
	return s, nil
}

func (s *Server) initTemplates() error {
	pages := []string{
		"dashboard.html",
		"wan.html",
		"ap.html",
		"lan.html",
		"vpn_wireguard.html",
		"vpn_ipsec.html",
	}

	funcMap := template.FuncMap{
		"toJSON": func(v interface{}) (template.JS, error) {
			b, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				return "", err
			}
			return template.JS(b), nil
		},
		"hasString": func(slice []string, val string) bool {
			for _, s := range slice {
				if s == val {
					return true
				}
			}
			return false
		},
	}

	// Parse layout + page templates
	for _, page := range pages {
		tmpl, err := template.New(page).Funcs(funcMap).ParseFS(EmbedFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			return fmt.Errorf("failed parsing template %s: %w", page, err)
		}
		s.templates[page] = tmpl
	}

	// Standalone setup and login templates
	setupTmpl, err := template.New("setup.html").Funcs(funcMap).ParseFS(EmbedFS, "templates/setup.html")
	if err != nil {
		return fmt.Errorf("failed parsing setup template: %w", err)
	}
	s.templates["setup.html"] = setupTmpl

	loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(EmbedFS, "templates/login.html")
	if err != nil {
		return fmt.Errorf("failed parsing login template: %w", err)
	}
	s.templates["login.html"] = loginTmpl

	// Partial templates
	scanTmpl, err := template.New("wan_scan_partial.html").Funcs(funcMap).ParseFS(EmbedFS, "templates/wan_scan_partial.html")
	if err != nil {
		return fmt.Errorf("failed parsing wan_scan_partial: %w", err)
	}
	s.templates["wan_scan_partial.html"] = scanTmpl

	return nil
}

func (s *Server) setupRoutes() {
	_ = mime.AddExtensionType(".woff", "font/woff")
	_ = mime.AddExtensionType(".woff2", "font/woff2")

	// Static Assets with caching
	staticSub, err := fs.Sub(EmbedFS, "static")
	if err != nil {
		log.Fatalf("failed to open static embedded sub-filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(staticSub))
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		if strings.HasSuffix(r.URL.Path, ".woff") || strings.HasSuffix(r.URL.Path, ".woff2") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		// Handle legacy / cached requests looking for fonts relative to css/
		if strings.HasPrefix(r.URL.Path, "css/fonts/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "css/")
		}
		fileServer.ServeHTTP(w, r)
	})))

	// Auth Endpoints
	s.mux.HandleFunc("GET /setup", s.handleSetupGet)
	s.mux.HandleFunc("POST /setup", s.handleSetupPost)
	s.mux.HandleFunc("GET /login", s.handleLoginGet)
	s.mux.HandleFunc("POST /login", s.handleLoginPost)
	s.mux.HandleFunc("POST /logout", s.handleLogout)

	// Dashboard
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	s.mux.HandleFunc("GET /dashboard", s.handleDashboard)

	// WAN
	s.mux.HandleFunc("GET /wan", s.handleWANGet)
	s.mux.HandleFunc("POST /wan", s.handleWANPost)
	s.mux.HandleFunc("GET /wan/scan", s.handleWANScan)

	// Access Point
	s.mux.HandleFunc("GET /ap", s.handleAPGet)
	s.mux.HandleFunc("POST /ap", s.handleAPPost)

	// LAN
	s.mux.HandleFunc("GET /lan", s.handleLANGet)
	s.mux.HandleFunc("POST /lan", s.handleLANPost)

	// VPNs
	s.mux.HandleFunc("GET /vpn/wireguard", s.handleWireGuardGet)
	s.mux.HandleFunc("POST /vpn/wireguard", s.handleWireGuardPost)
	s.mux.HandleFunc("POST /vpn/wireguard/keygen", s.handleWireGuardKeygen)
	s.mux.HandleFunc("GET /vpn/ipsec", s.handleIPSecGet)
	s.mux.HandleFunc("POST /vpn/ipsec", s.handleIPSecPost)

	// Staged Config Management
	s.mux.HandleFunc("POST /config/push", s.handleConfigPush)
	s.mux.HandleFunc("POST /config/discard", s.handleConfigDiscard)
}

// ServeHTTP implements http.Handler with security headers and authentication middleware.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Security Headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Pass through auth manager middleware
	s.authMgr.RequireAuth(s.mux).ServeHTTP(w, r)
}

// BaseViewData constructs standard template context including staged changes status.
func (s *Server) baseViewData(activeNav string) map[string]interface{} {
	alertMsg, alertType := s.applier.GetAlert()
	diffs := s.cfgMgr.GetDiff()

	leases, _ := s.sysMgr.GetDHCPLeases(s.sysRoot)

	liveCfg := s.cfgMgr.GetLive()
	wanIface := liveCfg.WAN.Interface
	if wanIface == "" {
		if liveCfg.WAN.Mode == "wireless" {
			wanIface = "wlan0"
		} else {
			wanIface = "eth0"
		}
	}
	wanStatus := s.sysMgr.GetWANStatus(wanIface)

	return map[string]interface{}{
		"ActiveNav":         activeNav,
		"LiveConfig":        liveCfg,
		"StagedConfig":      s.cfgMgr.GetStaged(),
		"HasStagedChanges":  s.cfgMgr.HasStagedChanges(),
		"StagedDiffs":       diffs,
		"AlertBanner":       alertMsg,
		"AlertType":         alertType,
		"Leases":            leases,
		"WANStatus":         wanStatus,
		"IPSecLive":         network.GetIPSecLiveStatus(s.mock),
		"NetworkInterfaces": network.ListNetworkInterfaces(),
	}
}

// RedirectBack redirects the browser back to the Referer URL or fallback.
func redirectBack(w http.ResponseWriter, r *http.Request, fallback string) {
	ref := r.Header.Get("Referer")
	if ref == "" || !strings.Contains(ref, r.Host) {
		ref = fallback
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
