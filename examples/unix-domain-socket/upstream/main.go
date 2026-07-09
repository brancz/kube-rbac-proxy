package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	socketPath := "/sockets/app.sock"
	if p := os.Getenv("SOCKET_PATH"); p != "" {
		socketPath = p
	}

	// Clean up stale socket file
	os.Remove(socketPath)

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", socketPath, err)
		os.Exit(1)
	}
	defer l.Close()

	// Make the socket accessible by other users in the pod
	if err := os.Chmod(socketPath, 0666); err != nil {
		fmt.Fprintf(os.Stderr, "failed to chmod socket: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintln(w, "# HELP version Version information about this binary")
		fmt.Fprintln(w, "# TYPE version gauge")
		fmt.Fprintln(w, `version{version="v0.1.0"} 0`)
	})

	fmt.Printf("listening on unix socket %s\n", socketPath)
	if err := http.Serve(l, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
