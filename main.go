package main

import (
	"log"
	"net/http"
	"os"

	"github.com/emicklei/go-restful"
)

func main() {
	ryp := RypResource{}

	wsContainer := restful.NewContainer()
	ryp.Register(wsContainer)
	restful.TraceLogger(log.New(os.Stdout, "[] ", log.LstdFlags|log.Lshortfile))
	server := &http.Server{Addr: ":8001", Handler: wsContainer}

	log.Printf("Listening on %s", "http://Localhost/8001")
	log.Fatal(server.ListenAndServe())
}
