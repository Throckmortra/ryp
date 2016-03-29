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
	server := &http.Server{Addr: ":" + os.Getenv("PORT"), Handler: wsContainer}

	log.Printf("Listening on %s", "port "+os.Getenv("PORT"))
	log.Fatal(server.ListenAndServe())
}
