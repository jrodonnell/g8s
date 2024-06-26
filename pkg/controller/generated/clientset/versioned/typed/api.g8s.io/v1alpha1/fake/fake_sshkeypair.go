/*
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
*/
// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeSSHKeyPairs implements SSHKeyPairInterface
type FakeSSHKeyPairs struct {
	Fake *FakeApiV1alpha1
	ns   string
}

var sshkeypairsResource = v1alpha1.SchemeGroupVersion.WithResource("sshkeypairs")

var sshkeypairsKind = v1alpha1.SchemeGroupVersion.WithKind("SSHKeyPair")

// Get takes name of the sSHKeyPair, and returns the corresponding sSHKeyPair object, and an error if there is any.
func (c *FakeSSHKeyPairs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.SSHKeyPair, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(sshkeypairsResource, c.ns, name), &v1alpha1.SSHKeyPair{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.SSHKeyPair), err
}

// List takes label and field selectors, and returns the list of SSHKeyPairs that match those selectors.
func (c *FakeSSHKeyPairs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.SSHKeyPairList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(sshkeypairsResource, sshkeypairsKind, c.ns, opts), &v1alpha1.SSHKeyPairList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.SSHKeyPairList{ListMeta: obj.(*v1alpha1.SSHKeyPairList).ListMeta}
	for _, item := range obj.(*v1alpha1.SSHKeyPairList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested sSHKeyPairs.
func (c *FakeSSHKeyPairs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(sshkeypairsResource, c.ns, opts))

}

// Create takes the representation of a sSHKeyPair and creates it.  Returns the server's representation of the sSHKeyPair, and an error, if there is any.
func (c *FakeSSHKeyPairs) Create(ctx context.Context, sSHKeyPair *v1alpha1.SSHKeyPair, opts v1.CreateOptions) (result *v1alpha1.SSHKeyPair, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(sshkeypairsResource, c.ns, sSHKeyPair), &v1alpha1.SSHKeyPair{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.SSHKeyPair), err
}

// Update takes the representation of a sSHKeyPair and updates it. Returns the server's representation of the sSHKeyPair, and an error, if there is any.
func (c *FakeSSHKeyPairs) Update(ctx context.Context, sSHKeyPair *v1alpha1.SSHKeyPair, opts v1.UpdateOptions) (result *v1alpha1.SSHKeyPair, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(sshkeypairsResource, c.ns, sSHKeyPair), &v1alpha1.SSHKeyPair{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.SSHKeyPair), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeSSHKeyPairs) UpdateStatus(ctx context.Context, sSHKeyPair *v1alpha1.SSHKeyPair, opts v1.UpdateOptions) (*v1alpha1.SSHKeyPair, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(sshkeypairsResource, "status", c.ns, sSHKeyPair), &v1alpha1.SSHKeyPair{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.SSHKeyPair), err
}

// Delete takes name of the sSHKeyPair and deletes it. Returns an error if one occurs.
func (c *FakeSSHKeyPairs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteActionWithOptions(sshkeypairsResource, c.ns, name, opts), &v1alpha1.SSHKeyPair{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSSHKeyPairs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(sshkeypairsResource, c.ns, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.SSHKeyPairList{})
	return err
}

// Patch applies the patch and returns the patched sSHKeyPair.
func (c *FakeSSHKeyPairs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.SSHKeyPair, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(sshkeypairsResource, c.ns, name, pt, data, subresources...), &v1alpha1.SSHKeyPair{})

	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.SSHKeyPair), err
}
