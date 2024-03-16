package webhook

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"k8s.io/klog/v2"
)

func Serve(ctx context.Context, logger klog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/mutate", handleMutate)

	s := http.Server{
		Addr:           ":8443",
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	err := s.ListenAndServeTLS("./cert.pem", "./key.pem")

	if err != nil {
		logger.Error(err, "Error starting webhook server")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/mutate", http.StatusFound)
}

func handleMutate(w http.ResponseWriter, r *http.Request) {
	os.Exit(0)
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
	}

	mutated, err := Mutate(body)
	w.WriteHeader(http.StatusOK)
	w.Write(mutated)
}
