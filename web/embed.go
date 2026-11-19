package web

import "embed"

//go:embed templates/* static/*
var EmbedFS embed.FS
