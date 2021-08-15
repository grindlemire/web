package main

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/grindlemire/web/httpserver"
	"github.com/vrecan/death"
)

func main() {

	d := death.NewDeath(syscall.SIGINT, syscall.SIGTERM)
	goRoutines := []io.Closer{}
	s, err := httpserver.NewServer()
	if err != nil {
		fmt.Printf("Error creating server: %s\n", err)
		os.Exit(1)
	}
	s.Start()
	goRoutines = append(goRoutines, s)

	err = d.WaitForDeath(goRoutines)
}
