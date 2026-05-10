package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"netwatch/internal/api"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:8080", "HTTP listen address")
	iface := flag.String("interface", "", "network interface for XDP flow monitoring")
	unsafeNoAuth := flag.Bool("unsafe-no-auth", false, "disable bearer token authentication")
	flag.Parse()

	token := api.TokenFromEnv()
	if token == "" && !*unsafeNoAuth {
		log.Fatal("NETWATCH_TOKEN must be set unless --unsafe-no-auth is used")
	}

	server := api.New(api.Config{
		Token:        token,
		UnsafeNoAuth: *unsafeNoAuth,
		Interface:    *iface,
	})

	fmt.Printf("netwatch API listening on http://%s\n", *listen)
	if err := http.ListenAndServe(*listen, server.Handler()); err != nil {
		log.Fatal(err)
	}
}
