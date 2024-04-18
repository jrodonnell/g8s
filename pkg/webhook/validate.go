package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer/json"

	"k8s.io/klog/v2"

	g8sv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	"github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned/scheme"
)

type allowlistToValidate struct {
	g8sv1alpha1.Allowlist
}

type result struct {
	metav1.Status
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	logger := klog.FromContext(context.Background())
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		logger.Error(err, "error reading AdmissionReview")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
	}

	denied := result{
		metav1.Status{
			TypeMeta: metav1.TypeMeta{
				Kind:       "G8sValidationError",
				APIVersion: "api.g8s.io/v1alpha1",
			},
			ListMeta: metav1.ListMeta{},
			Status:   "Failure",
			Message:  "Validation Failed",
		},
	}

	// get AdmisionReview and AdmissionResponse objects to use for logic
	admissionReview := admissionv1.AdmissionReview{}
	err = json.Unmarshal(body, &admissionReview)
	admissionResponse := admissionv1.AdmissionResponse{
		Allowed: true,
		UID:     admissionReview.Request.UID,
	}

	if err != nil {
		logger.Error(err, "error unmarshaling AdmissionReview")
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
		admissionResponse.Allowed = false
	}

	// get body of Allowlist to validate
	allowlist := &allowlistToValidate{}
	serializer := serializer.NewSerializerWithOptions(serializer.DefaultMetaFactory, scheme.Scheme, scheme.Scheme, serializer.SerializerOptions{})
	_, _, err = serializer.Decode(admissionReview.Request.Object.Raw, &schema.GroupVersionKind{}, allowlist)
	fmt.Println(err)
	if err != nil {
		logger.Error(err, "error decoding Object in Admission Review")
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
		admissionResponse.Allowed = false
	} else {
		logger.Info("Validating Allowlist", "Allowlist.ObjectMeta.Name", allowlist.ObjectMeta.Name)
	}

	for _, g := range g8sv1alpha1.G8sTypes {
		switch g {
		case "Logins":
			for ig, g := range allowlist.Spec.Logins {
				for it, t := range g.Targets {
					if t.Namespace == "g8s" {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Cannot target g8s namespace: .spec.%s[%d].targets[%d]", "logins", it, ig)
						admissionResponse.Result = &denied.Status
					}

					_, err := metav1.LabelSelectorAsSelector(&t.Selector)
					if err != nil {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Invalid Selector: .spec.%s[%d].targets[%d]", "logins", it, ig)
						admissionResponse.Result = &denied.Status
					}
				}
			}
		case "SelfSignedTLSBundles":
			for ig, g := range allowlist.Spec.SelfSignedTLSBundles {
				for it, t := range g.Targets {
					if t.Namespace == "g8s" {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Cannot target g8s namespace: .spec.%s[%d].targets[%d]", "selfSignedTLSBundles", it, ig)
						admissionResponse.Result = &denied.Status
					}

					_, err := metav1.LabelSelectorAsSelector(&t.Selector)
					if err != nil {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Invalid Selector: .spec.%s[%d].targets[%d]", "selfSignedTLSBundles", it, ig)
						admissionResponse.Result = &denied.Status
					}
				}
			}
		case "SSHKeyPairs":
			for ig, g := range allowlist.Spec.SSHKeyPairs {
				for it, t := range g.Targets {
					if t.Namespace == "g8s" {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Cannot target g8s namespace: .spec.%s[%d].targets[%d]", "sshKeyPairs", it, ig)
						admissionResponse.Result = &denied.Status
					}

					_, err := metav1.LabelSelectorAsSelector(&t.Selector)
					if err != nil {
						admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "validation-error"}
						admissionResponse.Allowed = false
						denied.Message = fmt.Sprintf("Invalid Selector: .spec.%s[%d].targets[%d]", "sshKeyPairs", it, ig)
						admissionResponse.Result = &denied.Status
					}
				}
			}
		}
	}

	admissionReview.Response = &admissionResponse
	resp, _ := json.Marshal(admissionReview)
	_, err = w.Write(resp)

	if err != nil {
		logger.Error(err, "error submitting AdmissionReview to kube-apiserver")
	}

	if admissionResponse.Allowed {
		logger.Info("Allowlist validated, AdmissionReview submitted to kube-apiserver", "Allowlist.ObjectMeta.Name", allowlist.ObjectMeta.Name)
	} else {
		logger.Info("Allowlist not valid, AdmissionResponse.Allowed == false", "Allowlist.ObjectMeta.Name", allowlist.ObjectMeta.Name)
	}
}
