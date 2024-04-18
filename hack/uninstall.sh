#!/bin/bash

export MANIFESTS_DIR="../manifests/install"

### verify that dependencies are present
if ! command -v yq >/dev/null ; then
    echo "'yq' command not found, please install first."
    exit 1
elif ! command -v kubectl >/dev/null ; then
    echo "'kubectl' command not found, please install first."
    exit 1
fi

WORKDIR=$(mktemp -d) && pushd $WORKDIR

curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/allowlist.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/controller.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/crds.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/webhook.yaml

popd
kubectl delete -f $WORKDIR
rm -rf $WORKDIR