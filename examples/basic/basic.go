package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/grindlemire/web"
)

func main() {
	e := web.Endpoint{
		Path:   "/",
		Method: []string{http.MethodGet},
		Handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello world"))
		},
	}

	s, err := web.NewServer(
		web.HTTPPort(8080),
		web.AddEndpoint(e),
	)
	if err != nil {
		fmt.Printf("Error creating server: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Go to http://localhost:8080 to see the page\n")

	// StartAndListen blocks like the ususal http.ListenAndServe call
	s.StartAndListen()
}