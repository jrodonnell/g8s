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

curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/namespace.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/allowlist.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/controller.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/crds.yaml
curl -sSOL https://raw.githubusercontent.com/jrodonnell/g8s/main/manifests/install/webhook.yaml

kubectl apply -f namespace.yaml
kubectl apply -f crds.yaml
kubectl apply -f controller.yaml
kubectl wait --for=condition=Ready pod -l app=g8s-controller -n g8s
kubectl wait --for=jsonpath='{.status.ready}'=true selfsignedtlsbundle/g8s-webhook -n g8s --timeout=15s
CACERT_PEM=$(kubectl get secret selfsignedtlsbundle-g8s-webhook -n g8s -o yaml | yq -r '.data."cacert.pem"')
sed -i "s/REPLACE_THIS/\"$CACERT_PEM\"/g" webhook.yaml

kubectl apply -f webhook.yaml
kubectl wait --for=condition=Ready pod -l app=g8s-webhook -n g8s
kubectl apply -f allowlist.yaml

popd && rm -rf $WORKDIR
