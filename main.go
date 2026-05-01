package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Config struct {
	LogLimit     int
	LoadBalancer LoadBalancerConfig
	Policies     []Policy
	Routes       []Route
	ActiveTab    string
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type APIKey struct {
	ID        int
	Key       string
	KeyPrefix string
	UserID    int
	CreatedAt time.Time
}

type LoadBalancerConfig struct {
	Mode           string
	ClientIPHeader string
	StripPort      bool
}

type Route struct {
	Name        string
	PathPrefix  string
	Target      string
	PolicyName  string
	StripPrefix bool
}

const defaultDBPath = "waiteway.db"

func main() {
	dbPath := defaultDBPath
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	store, err := openStore(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	if !store.HasRoutes() {
		store.AddRoute(Route{
			Name:       "example",
			PathPrefix: "/api/example",
			Target:     "http://localhost:3000",
		})
	}

	if err := store.EnsureFirstAdmin(os.Getenv("WAITEWAY_ADMIN_USERNAME"), os.Getenv("WAITEWAY_ADMIN_PASSWORD")); err != nil {
		log.Fatal(err)
	}

	config, err := store.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	listen := envOrDefault("WAITEWAY_LISTEN", ":8080")
	adminListen := envOrDefault("WAITEWAY_ADMIN_LISTEN", ":9090")

	gateway, err := newGateway(store, config)
	if err != nil {
		log.Fatal(err)
	}

	gwServer := &http.Server{Addr: listen, Handler: gateway.gatewayHandler()}
	adminServer := &http.Server{Addr: adminListen, Handler: gateway.adminHandler()}

	go func() {
		log.Printf("waiteway admin listening on %s", adminListen)
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	go func() {
		log.Printf("waiteway gateway listening on %s", listen)
		if err := gwServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Printf("waiteway shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = gwServer.Shutdown(ctx)
	_ = adminServer.Shutdown(ctx)
	gateway.Close()
	store.Close()
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

