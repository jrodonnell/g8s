package v1alpha1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strconv"
	"strings"

	"github.com/charmbracelet/keygen"
	"github.com/crossplane/crossplane-runtime/pkg/password"
	"github.com/jrodonnell/g8s/controller/apis/api.g8s.io/v1alpha1"
	g8sv1alpha1 "github.com/jrodonnell/g8s/controller/apis/api.g8s.io/v1alpha1"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Meta struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// generators for gates
type G8s interface {
	getMeta() Meta
	Generate() map[string]string
	Rotate() map[string]string
}

func NewBackendSecret(g8s G8s, content map[string]string) *corev1.Secret {
	meta := g8s.getMeta()
	kind := meta.Kind
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.ToLower(kind + "-" + meta.GetName()),
			Namespace: meta.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&meta, g8sv1alpha1.SchemeGroupVersion.WithKind(kind)),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable:  boolPtr(true),
		StringData: content,
		Type:       "Opaque",
	}
}

func NewHistorySecret(g8s G8s, content map[string]string) *corev1.Secret {
	meta := g8s.getMeta()
	kind := meta.Kind
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      strings.ToLower(kind + "-" + meta.GetName() + "-history"),
			Namespace: meta.GetNamespace(),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(&meta, g8sv1alpha1.SchemeGroupVersion.WithKind(kind)),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable:  boolPtr(true),
		StringData: content,
		Type:       "Opaque",
	}
}

// Secret.Immutable requires a *bool, helper func to return that
func boolPtr(b bool) *bool {
	return &b
}

type history []string

type Login struct {
	v1alpha1.Login
	history
}

func NewLogin(l *v1alpha1.Login) *Login {
	return &Login{
		*l,
		[]string{},
	}
}

func (l Login) getMeta() Meta {
	return Meta{
		metav1.TypeMeta{
			Kind:       "Login",
			APIVersion: "api.g8s.io/v1alpha",
		},
		l.ObjectMeta,
	}
}

// errors can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
func (l Login) Generate() map[string]string {
	settings := password.Settings{
		Length:       int(l.Spec.Password.Length),
		CharacterSet: l.Spec.Password.CharacterSet,
	}

	pwstr, _ := settings.Generate()

	return map[string]string{
		"password": pwstr,
	}
}

func (l Login) Rotate() map[string]string {
	newPw := l.Generate()
	newHistory := append([]string{newPw["password"]}, l.history...)
	newData := make(map[string]string)

	for i, pw := range newHistory {
		hist := "password-" + strconv.Itoa(i)
		newData[hist] = pw
	}

	return newData
}

type SSHKeyPair struct {
	v1alpha1.SSHKeyPair
	history
}

func NewSSHKeyPair(s *v1alpha1.SSHKeyPair) *SSHKeyPair {
	return &SSHKeyPair{
		*s,
		[]string{},
	}
}

func (ssh SSHKeyPair) getMeta() Meta {
	return Meta{
		metav1.TypeMeta{
			Kind:       "SSHKeyPair",
			APIVersion: "api.g8s.io/v1alpha",
		},
		ssh.ObjectMeta,
	}
}

// errors can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
func (ssh SSHKeyPair) Generate() map[string]string {
	ktconv := keygen.KeyType(ssh.Spec.KeyType)
	opts := []keygen.Option{(keygen.WithKeyType(ktconv)), keygen.WithBitSize(ssh.Spec.BitSize)}

	kp, _ := keygen.New("", opts...)

	pub := kp.RawAuthorizedKey()
	pubStr := string(pub[:])

	key := kp.RawPrivateKey()
	keyStr := string(key[:])

	return map[string]string{
		"ssh.pub": pubStr,
		"ssh.key": keyStr,
	}
}

func (ssh SSHKeyPair) Rotate() map[string]string {
	newSSHKeyPair := ssh.Generate()
	newHistory := append([]string{newSSHKeyPair["ssh.pub"]}, newSSHKeyPair["ssh.key"])
	newHistory = append(newHistory, ssh.history...)
	newData := make(map[string]string)

	count := 0
	hist := ""
	for i, ssh := range newHistory {
		mod := i % 2

		if mod == 0 {
			hist = "ssh.pub-" + strconv.Itoa(count)
		} else if mod == 1 {
			hist = "ssh.key-" + strconv.Itoa(count)
			count++
		}
		newData[hist] = ssh
	}

	return newData
}

type KubeTLSBundle struct {
	context.Context
	v1alpha1.KubeTLSBundle
	history
	kubernetes.Clientset
}

func NewKubeTLSBundle(ctx context.Context, ktls *v1alpha1.KubeTLSBundle, c kubernetes.Clientset) *KubeTLSBundle {
	return &KubeTLSBundle{
		ctx,
		*ktls,
		[]string{},
		c,
	}
}

func (ssh KubeTLSBundle) getMeta() Meta {
	return Meta{
		metav1.TypeMeta{
			Kind:       "KubeTLSBundle",
			APIVersion: "api.g8s.io/v1alpha",
		},
		ssh.ObjectMeta,
	}
}

// errors can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
func (ktls KubeTLSBundle) Generate() map[string]string {
	//	PrivateKey	crypto.PrivateKey
	//	CertificateSigningRequest	certsv1.CertificateSigningRequestSpec
	//	Certificate	certsv1.CertificateSigningRequestStatus
	cryptokey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := cryptokey.D.Bytes()

	x509csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          cryptokey.PublicKey,
		Subject: pkix.Name{
			Organization: []string{"g8s"},
			CommonName:   ktls.Spec.AppName,
		},
		//Extensions: []pkix.Extension{{
		//	// Key Usage, x509 4.2.1.3
		//	Id:       []int{15},
		//	Critical: true,
		//	Value:    []byte("101000000"),
		//},
		//{
		//	// Extended Key Usage, x509 4.2.1.12
		//	Id:       []int{37},
		//	Critical: false,
		//	Value:    []byte("id-kp 2"),
		//}},
	}

	rawcsr, _ := x509.CreateCertificateRequest(rand.Reader, &x509csr, key)

	kubecsr := certsv1.CertificateSigningRequest{
		TypeMeta:   ktls.TypeMeta,
		ObjectMeta: ktls.ObjectMeta,
		Spec: certsv1.CertificateSigningRequestSpec{
			Request:    rawcsr,
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages:     []certsv1.KeyUsage{certsv1.UsageDigitalSignature, certsv1.UsageKeyEncipherment},
		},
	}
	pendingcsr, _ := ktls.Clientset.CertificatesV1().CertificateSigningRequests().Create(ktls.Context, &kubecsr, metav1.CreateOptions{})
	approvedcsr, _ := ktls.Clientset.CertificatesV1().CertificateSigningRequests().UpdateApproval(ktls.Context, pendingcsr.ObjectMeta.Name, pendingcsr, metav1.UpdateOptions{})
	cert := approvedcsr.Status.Certificate

	//cacm, _ := ktls.Clientset.CoreV1().ConfigMaps(ktls.ObjectMeta.Namespace).Get(ktls.Context, "kube-root-ca.crt", metav1.GetOptions{})
	//ca := cacm.Data["ca.crt"]

	return map[string]string{
		"key.pem":  string(key),
		"cert.pem": string(cert),
	}
}

func (ktls KubeTLSBundle) Rotate() map[string]string {
	newKubeTLSBundle := ktls.Generate()
	newHistory := append([]string{newKubeTLSBundle["key.pem"]}, newKubeTLSBundle["cert.pem"])
	newHistory = append(newHistory, ktls.history...)
	newData := make(map[string]string)

	count := 0
	hist := ""
	for i, ssh := range newHistory {
		mod := i % 2

		if mod == 0 {
			hist = "key.pem-" + strconv.Itoa(count)
		} else if mod == 1 {
			hist = "cert.pem-" + strconv.Itoa(count)
			count++
		}
		newData[hist] = ssh
	}

	return newData
}
