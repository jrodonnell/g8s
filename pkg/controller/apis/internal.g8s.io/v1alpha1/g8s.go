package v1alpha1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/keygen"
	"github.com/crossplane/crossplane-runtime/pkg/password"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
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

func NewBackendSecret(g8s G8s, content map[string]string, secretType corev1.SecretType) *corev1.Secret {
	meta := g8s.GetMeta()
	name := strings.ToLower(meta.Kind + "-" + meta.Name)
	return &corev1.Secret{
		ObjectMeta: NewG8sObjectMeta(g8s, name),
		Immutable:  boolPtr(true),
		StringData: content,
		Type:       secretType,
	}
}

func NewHistorySecret(g8s G8s, content map[string]string) *corev1.Secret {
	meta := g8s.GetMeta()
	name := strings.ToLower(meta.Kind + "-" + meta.Name + "-history")
	return &corev1.Secret{
		ObjectMeta: NewG8sObjectMeta(g8s, name),
		Immutable:  boolPtr(true),
		StringData: content,
		Type:       "g8s.io/history",
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
	newPassword := l.Generate()
	newHistory := append([]string{newPassword["password"]}, l.history...)
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
	keyType := keygen.KeyType(ssh.Spec.KeyType)
	opts := []keygen.Option{(keygen.WithKeyType(keyType)), keygen.WithBitSize(ssh.Spec.BitSize)}

	keyPair, _ := keygen.New("", opts...)

	pub := keyPair.RawAuthorizedKey()
	pubStr := string(pub[:])

	key := keyPair.RawPrivateKey()
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

type SelfSignedTLSBundle struct {
	v1alpha1.SelfSignedTLSBundle
	history
}

func NewSelfSignedTLSBundle(sstls *v1alpha1.SelfSignedTLSBundle) *SelfSignedTLSBundle {
	sstls.TypeMeta = metav1.TypeMeta{
		Kind:       "SelfSignedTLSBundle",
		APIVersion: "api.g8s.io/v1alpha1",
	}
	return &SelfSignedTLSBundle{
		*sstls,
		[]string{},
	}
}

func (sstls SelfSignedTLSBundle) GetMeta() Meta {
	return Meta{
		sstls.TypeMeta,
		sstls.ObjectMeta,
	}
}

// errors can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
func (sstls SelfSignedTLSBundle) Generate() map[string]string {
	// create private key and self-signed CA cert for signing client's TLS cert
	ecdsaCAKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	caSerial = new(big.Int).Add(caSerial, big.NewInt(1))
	x509CACert := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   sstls.Spec.AppName,
			Organization: []string{"g8s"},
		},
		DNSNames:              sstls.Spec.SANs,
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertBytes, _ := x509.CreateCertificate(rand.Reader, x509CACert, x509CACert, &ecdsaCAKey.PublicKey, ecdsaCAKey)
	x509CACert, _ = x509.ParseCertificate(caCertBytes)

	// use CA cert to sign client's TLS cert
	ecdsaClientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientSerial := new(big.Int).Add(caSerial, big.NewInt(1))
	x509ClientCert := &x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName:   sstls.Spec.AppName,
			Organization: []string{"g8s"},
		},
		DNSNames:    sstls.Spec.SANs,
		NotBefore:   time.Now().UTC(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365).UTC(),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	clientCertBytes, err := x509.CreateCertificate(rand.Reader, x509ClientCert, x509CACert, &ecdsaClientKey.PublicKey, ecdsaCAKey)
	if err != nil {
		fmt.Println("clientCertBytes: ", err, string(clientCertBytes))
	}

	// encode these things to DER strings
	clientKeyBytes, _ := x509.MarshalECPrivateKey(ecdsaClientKey)
	clientKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: clientKeyBytes,
	}
	keyPEM := string(pem.EncodeToMemory(clientKeyBlock))

	clientCertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertBytes,
	}
	certPEM := string(pem.EncodeToMemory(clientCertBlock))

	caCertBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertBytes,
	}
	caCertPEM := string(pem.EncodeToMemory(caCertBlock))

	return map[string]string{
		"key.pem":    keyPEM,
		"cert.pem":   certPEM,
		"cacert.pem": caCertPEM,
	}
}

func (sstls SelfSignedTLSBundle) Rotate() map[string]string {
	newSelfSignedTLSBundle := sstls.Generate()
	newHistory := append([]string{newSelfSignedTLSBundle["key.pem"]}, newSelfSignedTLSBundle["cert.pem"], newSelfSignedTLSBundle["cacert.pem"])
	newHistory = append(newHistory, sstls.history...)
	newData := make(map[string]string)

	count := 0
	hist := ""
	for i, sstls := range newHistory {
		mod := i % 3

		if mod == 0 {
			hist = "key.pem-" + strconv.Itoa(count)
		} else if mod == 1 {
			hist = "cert.pem-" + strconv.Itoa(count)
		} else if mod == 2 {
			hist = "cacert.pem-" + strconv.Itoa(count)
			count++
		}
		newData[hist] = sstls
	}

	return newData
}
