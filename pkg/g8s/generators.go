package g8s

import (
	"strconv"

	"github.com/charmbracelet/keygen"
	"github.com/crossplane/crossplane-runtime/pkg/password"
	"github.com/the-gizmo-dojo/g8s/pkg/apis/api.g8s.io/v1alpha1"
)

type Gate interface {
	Generate() map[string]string
	Rotate() map[string]string
}

type passwordBackend struct {
	content string
	history []string
}

type Password struct {
	v1alpha1.PasswordSpec
	passwordBackend
}

func PasswordWithBackend(p *v1alpha1.PasswordSpec) Password {
	return Password{
		*p,
		passwordBackend{
			content: "",
			history: []string{},
		},
	}
}

// Answer.Content.(string)
func (pw Password) Generate() map[string]string {
	settings := password.Settings{
		Length:       int(pw.Length),
		CharacterSet: pw.CharacterSet,
	}

	// error can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
	pwstr, _ := settings.Generate()

	return map[string]string{
		"password": pwstr,
	}
}

func (pw Password) Rotate() map[string]string {
	newPassword := pw.Generate()
	newHistory := append([]string{newPassword["password"]}, pw.history...)
	newData := make(map[string]string)

	for i, pw := range newHistory {
		hist := "password-" + strconv.Itoa(i)
		newData[hist] = pw
	}

	return newData
}

type sshKeyPairBackend struct {
	content map[string]string
	history []string
}

type SSHKeyPair struct {
	v1alpha1.SSHKeyPair
	sshKeyPairBackend
}

func SSHKeyPairWithBackend(s *v1alpha1.SSHKeyPair) SSHKeyPair {
	return SSHKeyPair{
		*s,
		sshKeyPairBackend{
			content: map[string]string{},
			history: []string{},
		},
	}
}

func (ssh SSHKeyPair) Generate() map[string]string {
	ktconv := keygen.KeyType(ssh.Spec.KeyType)
	opts := []keygen.Option{(keygen.WithKeyType(ktconv)), keygen.WithBitSize(ssh.Spec.BitSize)}

	// error can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
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
