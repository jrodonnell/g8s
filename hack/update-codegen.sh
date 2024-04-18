#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

go get k8s.io/code-generator/cmd/conversion-gen
go mod download k8s.io/kube-openapi
go mod download github.com/go-openapi/jsonreference
go mod download github.com/go-openapi/swag
go mod download github.com/google/gnostic-models
go mod download github.com/go-openapi/jsonpointer
go mod download github.com/mailru/easyjson
go mod download github.com/josharian/intern

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

source "${SCRIPT_ROOT}/hack/kube_codegen.sh"

# generate the code with:
# --output-base    because this script should also be able to run inside the vendor dir of
#                  k8s.io/kubernetes. The output-base is needed for the generators to output into the vendor dir
#                  instead of the $GOPATH directly. For normal projects this can be dropped.
kube::codegen::gen_register \
    --input-pkg-root github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1 \
    --output-pkg-root github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1 \
    --output-base "$(dirname "${BASH_SOURCE[0]}")/../../../.." \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt"

kube::codegen::gen_helpers \
    --input-pkg-root github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1 \
    --output-base "$(dirname "${BASH_SOURCE[0]}")/../../../.." \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt"

kube::codegen::gen_client \
    --with-watch \
    --input-pkg-root github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1 \
    --output-pkg-root github.com/jrodonnell/g8s/pkg/controller/generated \
    --output-base "$(dirname "${BASH_SOURCE[0]}")/../../../.." \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt"