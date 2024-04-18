# g8s
## Introduction
`g8s` = generators for gates. G8s is a Kubernetes runtime application which provides two main pieces of functionality meant to be used in conjunction with each other:

1. Automatically generate values for certain kinds of secrets that apps depend on.
2. Enable cluster admins to propagate these secrets to any apps that need them.

It aims to be useful in the following situations when an app needs a certain value X in order to run:
1. You don't necessarily care what value X is, you just need a valid X to be there so that the app can start.
2. You don't have access to the value of X but the app needs it in order to work properly, e.g. X is a secret owned by admins but also needed by devs.

## Getting Started

### Prerequisites
- Kubernetes cluster, v1.24 and above

### Installation
`curl https://raw.githubusercontent.com/jrodonnell/g8s/main/hack/install.sh | bash`

### And then?
1. Create some objects in the `g8s` namespace, see the `/manifests/samples` folder for some examples
2. Create a namespace with the `g8s-injection: enabled` label or add it to an existing one
3. `kubectl edit allow g8s-master` to set some propagation rules into that namespace
    - If the rule is valid, backend Secrets should immediately propagate into the namespace
4. Deploy an app with labels that match your propagation rules into the namespace you created in step 2 and voilà!

### Uninstallation
`curl https://raw.githubusercontent.com/jrodonnell/g8s/main/hack/uninstall.sh | bash`

## Description
### Secret Creation
G8s comes with its own CustomResourceDefinitions which are all backed by regular Kubernetes Secret objects. At this time, the custom types are `Login`, `SelfSignedTLSBundle`, and `SSHKeyPair`.
For more information about these types as well as their backing Secret objects, see the Technical Specification in this repo's wiki. For some examples on how to create some g8s objects, see the
`/manifests/samples` directory.

Upon creation of one of these g8s types, the controller creates two Secrets: one which acts as the backend for the g8s type and one that stores its history. The backend Secret will contain 
the values generated and follows the naming pattern of `$TYPE-$NAME`; e.g. for a `Login` object named `root`, the backend Secret will be called `login-root`. The history Secret appends 
`-history` to this same name, so following this same example the history Secret would be called `login-root-history`. The history Secret currently only provides a source of redundancy, but 
will be used more extensively in the future when rotation for g8s types is implemented.

### Secret Propagation
G8s types will always stay in the namespace in which they are created, but their backend Secrets can be copied into other namespaces for other apps to use.
The `Allowlist` type is where these propagation rules are defined. There are currently a few assumptions hard-coded in (but could be configurable in the future):

1. You can create g8s objects in any namespace, but only those in the `g8s` namespace can be propagated.
2. Only one Allowlist, which must be called `g8s-master`, is supported.
3. Namespaces must have the label `g8s-injection: enabled` in order to receive propagated Secrets.

All propagated Secrets are owned by the Allowlist and will have an `ownerReference` set as such. Propagation takes place when the Allowlist is created or updated. If a target is removed
from the Allowlist, its previously propagated Secret will be deleted.

The Allowlist also serves as a configuration source for a MutatingWebhookConfiguration called `g8s-webhook`. This webhook watches all Pod admissions in namespaces with the label `g8s-injection: 
enabled`, checks to see if it matches any Target in the Allowlist based on the selector, and mutates the Pod accordingly if so. It will add Volumes for the backend Secret, VolumeMounts to 
`/var/run/secrets/g8s/$SECRETNAME`, and EnvVars for each value of the Secret. EnvVar naming follows the pattern of `$SECRETNAME_$DATAFIELD`, e.g. `LOGIN_ROOT_PASSWORD`.

There is also a ValidatingWebhookConfiguration which checks the Allowlist to ensure that the `g8s` namespace is not targeted in any propagation rules and that the selectors in the targets 
are valid.

## License

Copyright 2024 James Riley O'Donnell.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

