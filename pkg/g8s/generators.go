package g8s

import (
	"strconv"

	"github.com/crossplane/crossplane-runtime/pkg/password"
	"github.com/the-gizmo-dojo/g8s/pkg/apis/api.g8s.io/v1alpha1"
)

type Gate interface {
	Generate() Answer
	Rotate() map[string]string
}

type Answer struct {
	Content     any
	ContentType string
}

type Password struct {
	v1alpha1.Password
	backend
}

type backend struct {
	content string
	history []string
}

func PasswordWithBackend(pw *v1alpha1.Password) Password {
	return Password{
		*pw,
		backend{
			content: "",
			history: []string{},
		},
	}
}

// Answer.Content.(string)
func (pw Password) Generate() Answer {
	settings := password.Settings{
		Length:       int(pw.Spec.Length),
		CharacterSet: pw.Spec.CharacterSet,
	}

	// error can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
	pwstr, _ := settings.Generate()

	return Answer{
		Content:     pwstr,
		ContentType: "string",
	}
}

func (pw Password) Rotate() map[string]string {
	newContent := pw.Generate().Content.(string)
	newHistory := append([]string{newContent}, pw.history...)
	ans := make(map[string]string)

	for i, pw := range newHistory {
		histitem := "password-" + strconv.Itoa(i)
		ans[histitem] = pw
	}

	return ans
}
