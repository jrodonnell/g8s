package webhook

import (
	"context"
	"net/http"
	"time"

	"k8s.io/klog/v2"

	g8sinformers "github.com/jrodonnell/g8s/pkg/controller/generated/informers/externalversions/api.g8s.io/v1alpha1"
)

type patchOp struct {
	Op    string `json:"op,omitempty"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

func Serve(ctx context.Context, g8sInformer g8sinformers.AllowlistInformer) error {
	logger := klog.FromContext(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		handleMutate(ctx, w, r, g8sInformer)
	})
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		handleValidate(w, r)
	})

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
	<-ctx.Done()
	return err
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
