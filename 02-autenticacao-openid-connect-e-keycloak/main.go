package main

import (
	"context"
	"encoding/json"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

var (
	clientID = "app"
	clientSecret = "f9fb3255-49ed-451e-a40a-107954a5b1a8"
)

func main() {
	ctx := context.Background()

	provicer, err := oidc.NewProvider(ctx, "http://localhost:8080/auth/realms/demo")
	if err != nil {
		log.Fatal(err)
	}

	config := oauth2.config{
		ClientId: clientID,
		ClientSecret: clientSecret,
		Endpoint: provicer.Endpoint(),
		RedirectURL: "http://localhost:8081/auth/callback",
		Scopes: []strings{oidc.ScopeOpenID, "profile", "email", "roles"},
	}

	state := "magica"

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "failed to exchange token", http.StatusBadRequest)
			return
		}

		rawwIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token", http.StatusBadRequest)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			RawIDToken string
		} {
			oauth2Token, rawwIDToken
		}

		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Write(data)
	})

	log.Fatal(http.ListenAndServe(":8081", nil))
}