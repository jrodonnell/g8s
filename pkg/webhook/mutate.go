package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	serializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"

	g8sv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	g8sinformers "github.com/jrodonnell/g8s/pkg/controller/generated/informers/externalversions/api.g8s.io/v1alpha1"
)

type podToPatch struct {
	corev1.Pod
}

func handleMutate(ctx context.Context, w http.ResponseWriter, r *http.Request, g8sinformer g8sinformers.AllowlistInformer) {
	logger := klog.FromContext(ctx)
	body, err := io.ReadAll(r.Body)
	defer r.Body.Close()
	if err != nil {
		logger.Error(err, "error reading AdmissionReview")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s", err)
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
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "mutation-error"}
		admissionResponse.Allowed = false
	}

	// use requestPod as a vessel to facilitate proper mutation and creation of a JSONPatch
	requestPod := &podToPatch{}
	serializer := serializer.NewSerializerWithOptions(serializer.DefaultMetaFactory, scheme.Scheme, scheme.Scheme, serializer.SerializerOptions{})
	_, _, err = serializer.Decode(admissionReview.Request.Object.Raw, &schema.GroupVersionKind{}, requestPod)

	if err != nil {
		logger.Error(err, "error decoding Object in Admission Review")
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "mutation-error"}
		admissionResponse.Allowed = false
	} else {
		logger.Info("Determining if Pod should be mutated", "Pod.ObjectMeta.GenerateName", requestPod.ObjectMeta.GenerateName)
	}

	// get rules from Allowlist to determine if & how to mutate requestPod
	allow, err := g8sinformer.Lister().Get("g8s-master")

	if err != nil {
		logger.Error(err, "error getting Allowlist: g8s-master")
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "mutation-error"}
		admissionResponse.Allowed = false
	}

	// generate JSONPatch to submit with AdmissionResponse
	// targets = map[targetcontainer][]secretnames
	targets := requestPod.findTargets(ctx, allow)
	patch := requestPod.genPatch(targets)
	if patch != nil {
		patch = append(patch, patchOp{
			Op:    "add",
			Path:  "/metadata/annotations",
			Value: map[string]string{"g8s-webhook/allowlist": "g8s-master"},
		})
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		logger.Error(err, "error mutating Pod")
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/error": "mutation-error"}
		admissionResponse.Allowed = false
	}

	if admissionResponse.Allowed {
		patchtype := admissionv1.PatchTypeJSONPatch

		admissionResponse.Patch = patchBytes
		admissionResponse.PatchType = &patchtype
		admissionResponse.AuditAnnotations = map[string]string{"g8s-webhook/allowlist": "g8s-master"}
	}

	admissionReview.Response = &admissionResponse
	resp, _ := json.Marshal(admissionReview)
	_, err = w.Write(resp)

	if err != nil {
		logger.Error(err, "error submitting AdmissionReview to kube-apiserver")
	}

	if patch != nil {
		logger.Info("Pod should mutate, JSONPatch generated for AdmissionReview", "requestPod.ObjectMeta.GenerateName", requestPod.ObjectMeta.GenerateName)
	} else {
		logger.Info("Pod should NOT mutate, nil JSONPatch for AdmissionReview", "requestPod.ObjectMeta.GenerateName", requestPod.ObjectMeta.GenerateName)
	}
}

// targets = map[targetcontainer][]secretnames
func (requestPod *podToPatch) findTargets(ctx context.Context, allow *g8sv1alpha1.Allowlist) (targets map[string][]string) {
	logger := klog.FromContext(ctx)
	var requestPodContainerNames []string
	targets = make(map[string][]string)

	for _, rpc := range requestPod.Spec.Containers {
		requestPodContainerNames = append(requestPodContainerNames, rpc.Name)
	}

	requestPodLabels := labels.Set(requestPod.ObjectMeta.Labels)
	for _, g := range g8sv1alpha1.G8sTypes {
		switch g {
		case "Logins":
			for _, g := range allow.Spec.Logins {
				for _, t := range g.Targets {
					var reqMatches []bool
					selector, err := metav1.LabelSelectorAsSelector(&t.Selector)
					if err != nil {
						logger.Error(err, "error reading target's Selector")
					}

					requirements, err := labels.ParseToRequirements(selector.String())
					if err != nil {
						logger.Error(err, "error parsing Requirements from target's Selector")
					}

					for _, r := range requirements {
						if r.Matches(requestPodLabels) {
							reqMatches = append(reqMatches, r.Matches(requestPodLabels))
						}
					}

					if (len(requirements) > 0) && (len(requirements) == len(reqMatches)) {
						if t.Containers != nil { // target only containers specified in Allowlist
							for _, tc := range t.Containers {
								if slices.Contains(requestPodContainerNames, tc) {
									targets[tc] = append(targets[tc], "login-"+g.Name)
								}
							}
						} else {
							for _, rpcn := range requestPodContainerNames { // target all requestPod containers
								targets[rpcn] = append(targets[rpcn], "login-"+g.Name)
							}
						}
					}
				}
			}
		case "SelfSignedTLSBundles":
			for _, g := range allow.Spec.SelfSignedTLSBundles {
				for _, t := range g.Targets {
					var reqMatches []bool
					selector, err := metav1.LabelSelectorAsSelector(&t.Selector)

					if err != nil {
						logger.Error(err, "error reading target's Selector")
					}

					requirements, err := labels.ParseToRequirements(selector.String())
					if err != nil {
						logger.Error(err, "error parsing Requirements from target's Selector")
					}

					for _, r := range requirements {
						if r.Matches(requestPodLabels) {
							reqMatches = append(reqMatches, r.Matches(requestPodLabels))
						}
					}

					if (len(requirements) > 0) && (len(requirements) == len(reqMatches)) {
						if t.Containers != nil { // target only containers specified in Allowlist
							for _, tc := range t.Containers {
								if slices.Contains(requestPodContainerNames, tc) {
									targets[tc] = append(targets[tc], "selfsignedtlsbundle-"+g.Name)
								}
							}
						} else {
							for _, rpcn := range requestPodContainerNames { // target all requestPod containers
								targets[rpcn] = append(targets[rpcn], "selfsignedtlsbundle-"+g.Name)
							}
						}
					}
				}
			}
		case "SSHKeyPairs":
			for _, g := range allow.Spec.SSHKeyPairs {
				for _, t := range g.Targets {
					var reqMatches []bool
					selector, err := metav1.LabelSelectorAsSelector(&t.Selector)
					if err != nil {
						logger.Error(err, "error reading target's Selector")
					}

					requirements, err := labels.ParseToRequirements(selector.String())
					if err != nil {
						logger.Error(err, "error parsing Requirements from target's Selector")
					}

					for _, r := range requirements {
						if r.Matches(requestPodLabels) {
							reqMatches = append(reqMatches, r.Matches(requestPodLabels))
						}
					}

					if (len(requirements) > 0) && (len(requirements) == len(reqMatches)) {
						if t.Containers != nil { // target only containers specified in Allowlist
							for _, tc := range t.Containers {
								if slices.Contains(requestPodContainerNames, tc) {
									targets[tc] = append(targets[tc], "sshkeypair-"+g.Name)
								}
							}
						} else { // target all requestPod containers
							for _, rpcn := range requestPodContainerNames {
								targets[rpcn] = append(targets[rpcn], "sshkeypair-"+g.Name)
							}
						}
					}
				}
			}
		}
	}

	return targets
}

// targets = map[targetcontainername][]secretnames
func (requestPod *podToPatch) genPatch(targets map[string][]string) (patch []patchOp) {
	// skip everything and return nil if no targets
	if len(targets) == 0 {
		return patch
	}

	logger := klog.FromContext(context.Background())
	logger.Info("Generating JSONPatch", "Pod.ObjectMeta.GenerateName", requestPod.ObjectMeta.GenerateName)
	var allSecretNames []string
	var envVars []corev1.EnvVar
	var volumeMounts []corev1.VolumeMount

	// volumes must be initialized with the volumes already existing in requestPod, otherwise `add`ing a new
	// volume later in the jsonpatch for some reason deletes the automatically generated kube-api-access-* volume.
	// when this webhook gets the requestPod in the AdmissionReview, that volume is already present but initialized with all zero
	// values so it's probably due to how k8s executes the jsonpatch during its object instantiation under the hood.
	// in other words, its an order-of-operations-during-instantiation issue
	volumes := requestPod.Spec.Volumes

	var requestPodContainerNames []string
	for _, rpc := range requestPod.Spec.Containers {
		requestPodContainerNames = append(requestPodContainerNames, rpc.Name)
	}

	for t, s := range targets {
		envVars = nil
		volumeMounts = nil
		for _, sn := range s {
			g8sType := strings.Split(sn, "-")[0]
			g8sEnvVarName := strings.ReplaceAll(sn, "-", "_")

			switch g8sType {
			case "login":
				if !slices.Contains(allSecretNames, sn) {
					allSecretNames = append(allSecretNames, sn)
				}
				envVars = append(envVars, []corev1.EnvVar{{
					Name: strings.ToUpper(g8sEnvVarName + "_USERNAME"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "username",
						},
					},
				}, {
					Name: strings.ToUpper(g8sEnvVarName + "_PASSWORD"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "password",
						},
					},
				}}...)
				volumeMounts = append(volumeMounts, []corev1.VolumeMount{{
					Name:      sn,
					ReadOnly:  true,
					MountPath: "/var/run/secrets/g8s/" + sn,
				}}...)
			case "selfsignedtlsbundle":
				if !slices.Contains(allSecretNames, sn) {
					allSecretNames = append(allSecretNames, sn)
				}
				envVars = append(envVars, []corev1.EnvVar{{
					Name: strings.ToUpper(g8sEnvVarName + "_KEY"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "key.pem",
						},
					},
				}, {
					Name: strings.ToUpper(g8sEnvVarName + "_CERT"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "cert.pem",
						},
					},
				}, {
					Name: strings.ToUpper(g8sEnvVarName + "_CACERT"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "cacert.pem",
						},
					},
				}}...)
				volumeMounts = append(volumeMounts, []corev1.VolumeMount{{
					Name:      sn,
					ReadOnly:  true,
					MountPath: "/var/run/secrets/g8s/" + sn,
				}}...)
			case "sshkeypair":
				if !slices.Contains(allSecretNames, sn) {
					allSecretNames = append(allSecretNames, sn)
				}
				envVars = append(envVars, []corev1.EnvVar{{
					Name: strings.ToUpper(g8sEnvVarName + "_KEY"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "ssh.key",
						},
					},
				}, {
					Name: strings.ToUpper(g8sEnvVarName + "_PUB"),
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: sn,
							},
							Key: "ssh.pub",
						},
					},
				}}...)
				volumeMounts = append(volumeMounts, []corev1.VolumeMount{{
					Name:      sn,
					ReadOnly:  true,
					MountPath: "/var/run/secrets/g8s/" + sn,
				}}...)
			}
		}
		rpci := slices.Index(requestPodContainerNames, t)

		patch = append(patch, patchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/env", rpci),
			Value: envVars,
		})
		patch = append(patch, patchOp{
			Op:    "add",
			Path:  fmt.Sprintf("/spec/containers/%d/volumeMounts", rpci),
			Value: volumeMounts,
		})
	}

	// add Volumes last since those are at the PodSpec level
	for _, sn := range allSecretNames {
		volumes = append(volumes, []corev1.Volume{{
			Name: sn,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: sn,
				},
			},
		}}...)
	}

	patch = append(patch, patchOp{
		Op:    "add",
		Path:  "/spec/volumes",
		Value: volumes,
	})

	return patch
}
