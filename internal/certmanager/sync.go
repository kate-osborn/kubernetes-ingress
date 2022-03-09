/*
Copyright 2020 The cert-manager Authors.

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

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"

	"github.com/golang/glog"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cmlisters "github.com/jetstack/cert-manager/pkg/client/listers/certmanager/v1"
	"github.com/jetstack/cert-manager/pkg/controller"
	vsapi "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
)

const (
	reasonBadConfig         = "BadConfig"
	reasonCreateCertificate = "CreateCertificate"
	reasonUpdateCertificate = "UpdateCertificate"
	reasonDeleteCertificate = "DeleteCertificate"
)

var vsGVK = vsapi.SchemeGroupVersion.WithKind("VirtualServer")

// SyncFn is the reconciliation function passed to a certificate-shim's
// controller.
type SyncFn func(context.Context, *vsapi.VirtualServer) error

// SyncFnFor contains logic to reconcile any "Ingress-like" object.
//
// An "Ingress-like" object is a resource such as an Ingress, a Gateway or an
// HTTPRoute. Due to their similarity, the reconciliation function for them is
// common. Reconciling an Ingress-like object means looking at its annotations
// and creating a Certificate with matching DNS names and secretNames from the
// TLS configuration of the Ingress-like object.
func SyncFnFor(
	rec record.EventRecorder,
	cmClient clientset.Interface,
	cmLister cmlisters.CertificateLister,
	defaults controller.IngressShimOptions,
) SyncFn {
	return func(ctx context.Context, vs *vsapi.VirtualServer) error {
		issuerName, issuerKind, issuerGroup, err := issuerForIngressLike(defaults, vs)
		if err != nil {
			glog.Error(err, "failed to determine issuer to be used for ingress resource")
			rec.Eventf(vs, corev1.EventTypeWarning, reasonBadConfig, "Could not determine issuer for ingress due to bad annotations: %s",
				err)
			return nil
		}

		newCrts, updateCrts, err := buildCertificates(rec, cmLister, vs, issuerName, issuerKind, issuerGroup)
		if err != nil {
			return err
		}

		for _, crt := range newCrts {
			_, err := cmClient.CertmanagerV1().Certificates(crt.Namespace).Create(ctx, crt, metav1.CreateOptions{})
			if err != nil {
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, reasonCreateCertificate, "Successfully created Certificate %q", crt.Name)
		}

		for _, crt := range updateCrts {
			_, err := cmClient.CertmanagerV1().Certificates(crt.Namespace).Update(ctx, crt, metav1.UpdateOptions{})
			if err != nil {
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, reasonUpdateCertificate, "Successfully updated Certificate %q", crt.Name)
		}

		certs, err := cmLister.Certificates(vs.GetNamespace()).List(labels.Everything())
		if err != nil {
			return err
		}
		unrequiredCertNames := findCertificatesToBeRemoved(certs, vs)

		for _, certName := range unrequiredCertNames {
			err = cmClient.CertmanagerV1().Certificates(vs.GetNamespace()).Delete(ctx, certName, metav1.DeleteOptions{})
			if err != nil {
				return err
			}
			rec.Eventf(vs, corev1.EventTypeNormal, reasonDeleteCertificate, "Successfully deleted unrequired Certificate %q", certName)
		}

		return nil
	}
}

func buildCertificates(
	rec record.EventRecorder,
	cmLister cmlisters.CertificateLister,
	vs *vsapi.VirtualServer,
	issuerName, issuerKind, issuerGroup string,
) (new, update []*cmapi.Certificate, _ error) {
	var newCrts []*cmapi.Certificate
	var updateCrts []*cmapi.Certificate

	var hosts []string
	hosts = append(hosts, vs.Spec.Host)

	existingCrt, err := cmLister.Certificates(vs.Namespace).Get(vs.Spec.TLS.Secret)
	if !apierrors.IsNotFound(err) && err != nil {
		return nil, nil, err
	}

	var controllerGVK schema.GroupVersionKind = vsGVK

	crt := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:            vs.Spec.TLS.Secret,
			Namespace:       vs.Namespace,
			Labels:          vs.Labels,
			OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(vs, controllerGVK)},
		},
		Spec: cmapi.CertificateSpec{
			DNSNames:   hosts,
			SecretName: vs.Spec.TLS.Secret,
			IssuerRef: cmmeta.ObjectReference{
				Name:  issuerName,
				Kind:  issuerKind,
				Group: issuerGroup,
			},
			Usages: cmapi.DefaultKeyUsages(),
		},
	}

	vs = vs.DeepCopy()

	a, err := convertVsCmSpecToAnnotations(vs.Spec.TLS.CertManager)
	if err == nil {
		if err := translateAnnotations(crt, a); err != nil {
			return nil, nil, err
		}
	} else {
		return nil, nil, err
	}

	// check if a Certificate for this TLS entry already exists, and if it
	// does then skip this entry
	if existingCrt != nil {
		glog.Info("certificate already exists for this object, ensuring it is up to date")

		if metav1.GetControllerOf(existingCrt) == nil {
			glog.Info("certificate resource has no owner. refusing to update non-owned certificate resource for object")
		}

		if !metav1.IsControlledBy(existingCrt, vs) {
			glog.Info("certificate resource is not owned by this object. refusing to update non-owned certificate resource for object")
		}

		if !certNeedsUpdate(existingCrt, crt) {
			glog.Info("certificate resource is already up to date for object")
		}

		updateCrt := existingCrt.DeepCopy()

		updateCrt.Spec = crt.Spec
		updateCrt.Labels = crt.Labels

		updateCrts = append(updateCrts, updateCrt)
	} else {
		newCrts = append(newCrts, crt)
	}
	return newCrts, updateCrts, nil
}

func findCertificatesToBeRemoved(certs []*cmapi.Certificate, vs *vsapi.VirtualServer) []string {
	var toBeRemoved []string
	for _, crt := range certs {
		if !metav1.IsControlledBy(crt, vs) {
			continue
		}
		if !secretNameUsedIn(crt.Spec.SecretName, *vs) {
			toBeRemoved = append(toBeRemoved, crt.Name)
		}
	}
	return toBeRemoved
}

func secretNameUsedIn(secretName string, vs vsapi.VirtualServer) bool {
	return secretName == vs.Spec.TLS.Secret
}

// certNeedsUpdate checks and returns true if two Certificates differ.
func certNeedsUpdate(a, b *cmapi.Certificate) bool {
	if a.Name != b.Name {
		return true
	}

	// TODO: we may need to allow users to edit the managed Certificate resources
	// to add their own labels directly.
	// Right now, we'll reset/remove the label values back automatically.
	// Let's hope no other controllers do this automatically, else we'll start fighting...
	if !reflect.DeepEqual(a.Labels, b.Labels) {
		return true
	}

	if a.Spec.CommonName != b.Spec.CommonName {
		return true
	}

	if len(a.Spec.DNSNames) != len(b.Spec.DNSNames) {
		return true
	}

	for i := range a.Spec.DNSNames {
		if a.Spec.DNSNames[i] != b.Spec.DNSNames[i] {
			return true
		}
	}

	if a.Spec.SecretName != b.Spec.SecretName {
		return true
	}

	if a.Spec.IssuerRef.Name != b.Spec.IssuerRef.Name {
		return true
	}

	if a.Spec.IssuerRef.Kind != b.Spec.IssuerRef.Kind {
		return true
	}

	return false
}

// // setIssuerSpecificConfig configures given Certificate's annotation by reading
// // two Ingress-specific annotations.
// //
// // (1) The edit-in-place Ingress annotation allows the use of Ingress
// //     controllers that map a single IP address to a single Ingress
// //     resource, such as the GCE ingress controller. The the following
// //     annotation on an Ingress named "my-ingress":
// //
// //       acme.cert-manager.io/http01-edit-in-place: "true"
// //
// //     configures the Certificate with two annotations:
// //
// //       acme.cert-manager.io/http01-override-ingress-name: my-ingress
// //       cert-manager.io/issue-temporary-certificate: "true"
// //
// // (2) The ingress-class Ingress annotation allows users to override the
// //     Issuer's acme.solvers[0].http01.ingress.class. For example, on the
// //     Ingress:
// //
// //       acme.cert-manager.io/http01-ingress-class: traefik
// //
// //     configures the Certificate using the override-ingress-class annotation:
// //
// //       acme.cert-manager.io/http01-override-ingress-class: traefik
// func setIssuerSpecificConfig(crt *cmapi.Certificate, ingLike metav1.Object) {
// 	ingAnnotations := ingLike.GetAnnotations()
// 	if ingAnnotations == nil {
// 		ingAnnotations = map[string]string{}
// 	}

// 	// for ACME issuers
// 	editInPlaceVal := ingAnnotations[cmacme.IngressEditInPlaceAnnotationKey]
// 	editInPlace := editInPlaceVal == "true"
// 	if editInPlace {
// 		if crt.Annotations == nil {
// 			crt.Annotations = make(map[string]string)
// 		}
// 		crt.Annotations[cmacme.ACMECertificateHTTP01IngressNameOverride] = ingLike.GetName()
// 		// set IssueTemporaryCertificateAnnotation to true in order to behave
// 		// better when ingress-gce is being used.
// 		crt.Annotations[cmapi.IssueTemporaryCertificateAnnotation] = "true"
// 	}

// 	ingressClassVal, hasIngressClassVal := ingAnnotations[cmapi.IngressACMEIssuerHTTP01IngressClassAnnotationKey]
// 	if hasIngressClassVal {
// 		if crt.Annotations == nil {
// 			crt.Annotations = make(map[string]string)
// 		}
// 		crt.Annotations[cmacme.ACMECertificateHTTP01IngressClassOverride] = ingressClassVal
// 	}

// 	ingLike.SetAnnotations(ingAnnotations)
// }

// issuerForIngressLike determines the Issuer that should be specified on a
// Certificate created for the given ingress-like resource. If one is not set,
// the default issuer given to the controller is used. We look up the following
// Ingress annotations:
//
//   cert-manager.io/cluster-issuer
//   cert-manager.io/issuer
//   cert-manager.io/issuer-kind
//   cert-manager.io/issuer-group
func issuerForIngressLike(defaults controller.IngressShimOptions, vs *vsapi.VirtualServer) (name, kind, group string, err error) {
	var errs []string

	name = defaults.DefaultIssuerName
	kind = defaults.DefaultIssuerKind
	group = defaults.DefaultIssuerGroup

	annotations, err := getVsCmSpecIssuerAnnotations(vs.Spec.TLS.CertManager)
	if err != nil {
		return "", "", "", err
	}

	if annotations == nil {
		annotations = map[string]string{}
	}

	issuerName, issuerNameOK := annotations[cmapi.IngressIssuerNameAnnotationKey]
	if issuerNameOK {
		name = issuerName
		kind = cmapi.IssuerKind
	}

	clusterIssuerName, clusterIssuerNameOK := annotations[cmapi.IngressClusterIssuerNameAnnotationKey]
	if clusterIssuerNameOK {
		name = clusterIssuerName
		kind = cmapi.ClusterIssuerKind
	}

	kindName, kindNameOK := annotations[cmapi.IssuerKindAnnotationKey]
	if kindNameOK {
		kind = kindName
	}

	groupName, groupNameOK := annotations[cmapi.IssuerGroupAnnotationKey]
	if groupNameOK {
		group = groupName
	}

	if len(name) == 0 {
		errs = append(errs, "failed to determine issuer name to be used for virtualserver resource")
	}

	if issuerNameOK && clusterIssuerNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressIssuerNameAnnotationKey, cmapi.IngressClusterIssuerNameAnnotationKey))
	}

	if clusterIssuerNameOK && groupNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressClusterIssuerNameAnnotationKey, cmapi.IssuerGroupAnnotationKey))
	}

	if clusterIssuerNameOK && kindNameOK {
		errs = append(errs,
			fmt.Sprintf("both %q and %q may not be set",
				cmapi.IngressClusterIssuerNameAnnotationKey, cmapi.IssuerKindAnnotationKey))
	}

	if len(errs) > 0 {
		return "", "", "", errors.New(strings.Join(errs, ", "))
	}

	return name, kind, group, nil
}
