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

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	scheme "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SelfSignedTLSBundlesGetter has a method to return a SelfSignedTLSBundleInterface.
// A group's client should implement this interface.
type SelfSignedTLSBundlesGetter interface {
	SelfSignedTLSBundles(namespace string) SelfSignedTLSBundleInterface
}

// SelfSignedTLSBundleInterface has methods to work with SelfSignedTLSBundle resources.
type SelfSignedTLSBundleInterface interface {
	Create(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.CreateOptions) (*v1alpha1.SelfSignedTLSBundle, error)
	Update(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.UpdateOptions) (*v1alpha1.SelfSignedTLSBundle, error)
	UpdateStatus(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.UpdateOptions) (*v1alpha1.SelfSignedTLSBundle, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.SelfSignedTLSBundle, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.SelfSignedTLSBundleList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.SelfSignedTLSBundle, err error)
	SelfSignedTLSBundleExpansion
}

// selfSignedTLSBundles implements SelfSignedTLSBundleInterface
type selfSignedTLSBundles struct {
	client rest.Interface
	ns     string
}

// newSelfSignedTLSBundles returns a SelfSignedTLSBundles
func newSelfSignedTLSBundles(c *ApiV1alpha1Client, namespace string) *selfSignedTLSBundles {
	return &selfSignedTLSBundles{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the selfSignedTLSBundle, and returns the corresponding selfSignedTLSBundle object, and an error if there is any.
func (c *selfSignedTLSBundles) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.SelfSignedTLSBundle, err error) {
	result = &v1alpha1.SelfSignedTLSBundle{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SelfSignedTLSBundles that match those selectors.
func (c *selfSignedTLSBundles) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.SelfSignedTLSBundleList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.SelfSignedTLSBundleList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested selfSignedTLSBundles.
func (c *selfSignedTLSBundles) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a selfSignedTLSBundle and creates it.  Returns the server's representation of the selfSignedTLSBundle, and an error, if there is any.
func (c *selfSignedTLSBundles) Create(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.CreateOptions) (result *v1alpha1.SelfSignedTLSBundle, err error) {
	result = &v1alpha1.SelfSignedTLSBundle{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(selfSignedTLSBundle).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a selfSignedTLSBundle and updates it. Returns the server's representation of the selfSignedTLSBundle, and an error, if there is any.
func (c *selfSignedTLSBundles) Update(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.UpdateOptions) (result *v1alpha1.SelfSignedTLSBundle, err error) {
	result = &v1alpha1.SelfSignedTLSBundle{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		Name(selfSignedTLSBundle.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(selfSignedTLSBundle).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *selfSignedTLSBundles) UpdateStatus(ctx context.Context, selfSignedTLSBundle *v1alpha1.SelfSignedTLSBundle, opts v1.UpdateOptions) (result *v1alpha1.SelfSignedTLSBundle, err error) {
	result = &v1alpha1.SelfSignedTLSBundle{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		Name(selfSignedTLSBundle.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(selfSignedTLSBundle).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the selfSignedTLSBundle and deletes it. Returns an error if one occurs.
func (c *selfSignedTLSBundles) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *selfSignedTLSBundles) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched selfSignedTLSBundle.
func (c *selfSignedTLSBundles) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.SelfSignedTLSBundle, err error) {
	result = &v1alpha1.SelfSignedTLSBundle{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("selfsignedtlsbundles").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}