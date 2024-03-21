package webhook

import (
	"fmt"
)

func Mutate(body []byte) (resp []byte, err error) {
	/*
		TODO:
			- Get() Allowlist
			- check if Pod is owned by appsv1 object specified in Allowlist
			- if yes, mutate
			- create ClusterRoleBinding
	*/
	err = fmt.Errorf("")

	return []byte("RESPONSE"), err
}
