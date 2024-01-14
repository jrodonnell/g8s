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

type Login struct {
	v1alpha1.Login
	backend
}

type backend struct {
	content string
	history []string
}

func LoginWithBackend(l *v1alpha1.Login) Login {
	return Login{
		*l,
		backend{
			content: "",
			history: []string{},
		},
	}
}

// Answer.Content.(string)
func (l Login) Generate() Answer {
	settings := password.Settings{
		Length:       int(l.Spec.Length),
		CharacterSet: l.Spec.Password.CharacterSet,
	}

	// error can be ignored because if there's a problem it will be handled in the controller (processNextWorkItem will requeue it)
	lstr, _ := settings.Generate()

	return Answer{
		Content:     lstr,
		ContentType: "string",
	}
}

func (l Login) Rotate() map[string]string {
	newContent := l.Generate().Content.(string)
	newHistory := append([]string{newContent}, l.history...)
	ans := make(map[string]string)

	for i, l := range newHistory {
		histitem := "password-" + strconv.Itoa(i)
		ans[histitem] = l
	}

	return ans
}
