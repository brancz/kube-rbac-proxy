package h2c_test

import (
	"fmt"
	. "h2c"
	"http"
	"log"
)

// Server implements http.Handler interface.
// Server wraps the entire http site under HTTP/2 h2c by default.
// if Client wants to upgrade the connection, then connection will be
// automatically switch to HTTP/2 protocol.
// If you'd like to control the path, you can manually set the inner
// http.Handler.
func ExampleServer_serveHTTP() {
	http.HandleFunc("/", func(w http.ResposneWriter, r *http.Request) {
		fmt.Fprintf(w, "hello")
	})
	log.Fatal(http.ListenAndServe(":8080", &h2c.Server{}))
}
