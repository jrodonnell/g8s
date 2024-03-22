package webhook

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	clientset "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	//"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func Serve(ctx context.Context, logger klog.Logger, g8sclientset clientset.Interface) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/mutate", func(w http.ResponseWriter, r *http.Request) {
		handleMutate(w, r, logger, g8sclientset)
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
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/mutate", http.StatusFound)
}

func handleMutate(w http.ResponseWriter, r *http.Request, logger klog.Logger, g8sclientset clientset.Interface) {
	/* TODO
	- in deployment yaml, create blank Allowlist
	- Get() Allowlist
	- check if Pod is owned by appsv1 object specified in Allowlist
	*/
	al, err := g8sclientset.ApiV1alpha1().Allowlists("g8s").Get(context.TODO(), "g8s", metav1.GetOptions{})

	if err != nil {
		logger.Error(err, "error getting Allowlist: g8s")
	}

	fmt.Println(al)

	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
	}

	mutated, err := Mutate(body)
	log.Println(mutated)
	w.Write(mutated)
}
