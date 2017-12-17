package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/adamjacobmuller/captain/hook"
	"github.com/namsral/flag"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	var hookdir string
	var secret string

	flag.StringVar(&secret, "secret", "", "secret")
	flag.StringVar(&hookdir, "hookdir", "", "hookdir")

	flag.Parse()

	if hookdir == "" {
		log.Fatal("hookdir is required")
	}
	if secret == "" {
		log.Fatal("secret is required")
	}

	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: func(context.Context, string) error { return nil },
		Cache:      autocert.DirCache("/var/www/.cache"),
	}

	server := hook.NewServer(hookdir, secret)

	httpsPort := 443

	s := &http.Server{
		Handler:   server,
		Addr:      fmt.Sprintf(":%d", httpsPort),
		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
	}
	log.WithFields(log.Fields{
		"port": httpsPort,
	}).Info("listening for HTTPS connections")
	err := s.ListenAndServeTLS("", "")
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Fatal("ListenAndServeTLS failed")
	}
}
