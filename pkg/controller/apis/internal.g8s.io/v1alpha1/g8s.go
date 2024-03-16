package v1alpha1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"strconv"
	"strings"

	"github.com/charmbracelet/keygen"
	"github.com/crossplane/crossplane-runtime/pkg/password"
	"github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certsv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
)

type Meta struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}

// generators for gates
type G8s interface {
	GetMeta() Meta
	Generate() map[string]string
	Rotate() map[string]string
}

// use to get a standard ObjectMeta when creating objects
func NewG8sObjectMeta(g8s G8s, name string) metav1.ObjectMeta {
	meta := g8s.GetMeta()
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: meta.Namespace,
		Labels:    meta.Labels,
		OwnerReferences: []metav1.OwnerReference{
			*metav1.NewControllerRef(&meta, v1alpha1.SchemeGroupVersion.WithKind(meta.Kind)),
		},
		Annotations: map[string]string{
			"controller": "g8s",
		},
	}
}

func NewBackendSecret(g8s G8s, content map[string]string) *corev1.Secret {
	meta := g8s.GetMeta()
	name := strings.ToLower(meta.Kind + "-" + meta.Name)
	return &corev1.Secret{
		ObjectMeta: NewG8sObjectMeta(g8s, name),
		Immutable:  boolPtr(true),
		StringData: content,
		Type:       "Opaque",
	}
}

func NewHistorySecret(g8s G8s, content map[string]string) *corev1.Secret {
	meta := g8s.GetMeta()
	name := strings.ToLower(meta.Kind + "-" + meta.Name + "-history")
	return &corev1.Secret{
		ObjectMeta: NewG8sObjectMeta(g8s, name),
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
	l.TypeMeta = metav1.TypeMeta{
		Kind:       "Login",
		APIVersion: "api.g8s.io/v1alpha1",
	}
	return &Login{
		*l,
		[]string{},
	}
}

func (l Login) GetMeta() Meta {
	return Meta{
		l.TypeMeta,
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

func NewSSHKeyPair(ssh *v1alpha1.SSHKeyPair) *SSHKeyPair {
	ssh.TypeMeta = metav1.TypeMeta{
		Kind:       "SSHKeyPair",
		APIVersion: "api.g8s.io/v1alpha1",
	}
	return &SSHKeyPair{
		*ssh,
		[]string{},
	}
}

func (ssh SSHKeyPair) GetMeta() Meta {
	return Meta{
		ssh.TypeMeta,
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
	v1alpha1.KubeTLSBundle
	history
	certsv1client.CertificatesV1Interface
	CSRPEM  chan []byte
	CertPEM chan []byte
}

func NewKubeTLSBundle(ktls *v1alpha1.KubeTLSBundle, c certsv1client.CertificatesV1Interface) *KubeTLSBundle {
	ktls.TypeMeta = metav1.TypeMeta{
		Kind:       "KubeTLSBundle",
		APIVersion: "api.g8s.io/v1alpha1",
	}
	return &KubeTLSBundle{
		*ktls,
		[]string{},
		c,
		make(chan []byte),
		make(chan []byte),
	}
}

func (ktls KubeTLSBundle) GetMeta() Meta {
	return Meta{
		ktls.TypeMeta,
		ktls.ObjectMeta,
	}
}

// errors can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
func (ktls KubeTLSBundle) Generate() map[string]string {
	ecdsakey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privbytes, _ := x509.MarshalECPrivateKey(ecdsakey)
	privblock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privbytes,
	}
	keypem := string(pem.EncodeToMemory(privblock))

	// reference for how to get the public key
	// turns out i don't need it but it took a little while to figure out SO I'M KEEPING IT
	//
	//pubbytes, _ := x509.MarshalPKIXPublicKey(&ecdsakey.PublicKey)
	//pubblock := &pem.Block{
	//	Type:  "PUBLIC KEY",
	//	Bytes: pubbytes,
	//}
	//pubpem := string(pem.EncodeToMemory(pubblock))

	x509csr := x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          ecdsakey.PublicKey,
		Subject: pkix.Name{
			Organization: []string{"g8s"},
			CommonName:   ktls.Spec.AppName,
		},
	}

	csrbytes, _ := x509.CreateCertificateRequest(rand.Reader, &x509csr, ecdsakey)
	csrblock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrbytes,
	}
	csrpem := pem.EncodeToMemory(csrblock)

	// write PEM-encoded CSR to chan, wait for controller to return with PEM-encoded cert
	ktls.CSRPEM <- csrpem
	certpem := string(<-ktls.CertPEM)

	close(ktls.CSRPEM)
	close(ktls.CertPEM)

	return map[string]string{
		"key.pem":  keypem,
		"cert.pem": certpem,
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
