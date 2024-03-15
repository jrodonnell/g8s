package webhook

import (
	"net/http"
	"os"
)

func Serve() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/mutate", handleMutate)
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	os.Exit(0)
}

func handleMutate(w http.ResponseWriter, r *http.Request) {
	os.Exit(0)
}
