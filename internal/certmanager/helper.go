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
	"errors"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	vsapi "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
)

var (
	errNilCertificate           = errors.New("the supplied Certificate pointer was nil")
	errInvalidIngressAnnotation = errors.New("invalid ingress annotation")
)

// translateAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following Ingress:
//
//   kind: Ingress
//   metadata:
//     annotations:
//       cert-manager.io/common-name: example.com
//       cert-manager.io/duration: 2160h
//       cert-manager.io/renew-before: 1440h
//       cert-manager.io/usages: "digital signature,key encipherment"
//
// is mapped to the following Certificate:
//
//   kind: Certificate
//   spec:
//     commonName: example.com
//     duration: 2160h
//     renewBefore: 1440h
//     usages:
//       - digital signature
//       - key encipherment
func translateAnnotations(crt *cmapi.Certificate, ingLikeAnnotations map[string]string) error {
	if crt == nil {
		return errNilCertificate
	}

	if commonName, found := ingLikeAnnotations[cmapi.CommonNameAnnotationKey]; found {
		crt.Spec.CommonName = commonName
	}

	if duration, found := ingLikeAnnotations[cmapi.DurationAnnotationKey]; found {
		duration, err := time.ParseDuration(duration)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.DurationAnnotationKey, err)
		}
		crt.Spec.Duration = &metav1.Duration{Duration: duration}
	}

	if renewBefore, found := ingLikeAnnotations[cmapi.RenewBeforeAnnotationKey]; found {
		duration, err := time.ParseDuration(renewBefore)
		if err != nil {
			return fmt.Errorf("%w %q: %v", errInvalidIngressAnnotation, cmapi.RenewBeforeAnnotationKey, err)
		}
		crt.Spec.RenewBefore = &metav1.Duration{Duration: duration}
	}

	if usages, found := ingLikeAnnotations[cmapi.UsagesAnnotationKey]; found {
		var newUsages []cmapi.KeyUsage
		for _, usageName := range strings.Split(usages, ",") {
			usage := cmapi.KeyUsage(strings.Trim(usageName, " "))
			_, isKU := apiutil.KeyUsageType(usage)
			_, isEKU := apiutil.ExtKeyUsageType(usage)
			if !isKU && !isEKU {
				return fmt.Errorf("%w %q: invalid key usage name %q", errInvalidIngressAnnotation, cmapi.UsagesAnnotationKey, usageName)
			}
			newUsages = append(newUsages, usage)
		}
		crt.Spec.Usages = newUsages
	}
	return nil
}

// convertVsCmSpecToAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following VirtualServer TLS Cert-Manger config:
//
//       cert-manager:
//          <...>
//          CommonName: example.com
//     		Duration: 2160h
//     		RenewBefore: 1440h
//     		Usages:
//       		- digital signature
//       		- key encipherment
//
// is mapped to the following annotations:
//
//     annotations:
//       cert-manager.io/common-name: example.com
//       cert-manager.io/duration: 2160h
//       cert-manager.io/renew-before: 1440h
//       cert-manager.io/usages: "digital signature,key encipherment"
func convertVsCmSpecToAnnotations(vsCmSpec *vsapi.CertManager) (map[string]string, error) {
	ingLikeAnnotations := make(map[string]string)

	if vsCmSpec.CommonName != "" {
		ingLikeAnnotations[cmapi.CommonNameAnnotationKey] = vsCmSpec.CommonName
	}

	if vsCmSpec.Duration != "" {
		ingLikeAnnotations[cmapi.DurationAnnotationKey] = vsCmSpec.Duration
	}

	if vsCmSpec.RenewBefore != "" {
		ingLikeAnnotations[cmapi.DurationAnnotationKey] = vsCmSpec.RenewBefore
	}

	if vsCmSpec.Usages != "" {
		ingLikeAnnotations[cmapi.DurationAnnotationKey] = vsCmSpec.Usages
	}

	return ingLikeAnnotations, nil
}

// convertVsCmSpecToAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following VirtualServer TLS Cert-Manger config:
//
//       cert-manager:
//          <...>
//          ClusterIssuer: sample_issuer
//     		Issuer: sample_issuer
//     		IssuerKind: CA
//     		IssuerGroup: my_group
//
// is mapped to the following annotations:
//
//     annotations:
//   		cert-manager.io/cluster-issuer
//   		cert-manager.io/issuer
//   		cert-manager.io/issuer-kind
//   		cert-manager.io/issuer-group
func getVsCmSpecIssuerAnnotations(vsCmSpec *vsapi.CertManager) (map[string]string, error) {
	ingLikeAnnotations, err := getVsCmSpecShimAnnotations(vsCmSpec)
	if err != nil {
		return nil, err
	}

	if vsCmSpec.IssuerKind != "" {
		ingLikeAnnotations[cmapi.IssuerKindAnnotationKey] = vsCmSpec.IssuerKind
	}

	if vsCmSpec.IssuerGroup != "" {
		ingLikeAnnotations[cmapi.IssuerGroupAnnotationKey] = vsCmSpec.IssuerGroup
	}

	return ingLikeAnnotations, nil
}

// convertVsCmSpecToAnnotations updates the Certificate spec using the ingress-like
// annotations. For example, the following VirtualServer TLS Cert-Manger config:
//
//       cert-manager:
//          <...>
//          ClusterIssuer: sample_issuer
//     		Issuer: sample_issuer
//
// is mapped to the following annotations:
//
//     annotations:
//   		cert-manager.io/cluster-issuer
//   		cert-manager.io/issuer
func getVsCmSpecShimAnnotations(vsCmSpec *vsapi.CertManager) (map[string]string, error) {
	ingLikeAnnotations := make(map[string]string)

	if vsCmSpec.ClusterIssuer != "" {
		ingLikeAnnotations[cmapi.IngressClusterIssuerNameAnnotationKey] = vsCmSpec.ClusterIssuer
	}

	if vsCmSpec.Issuer != "" {
		ingLikeAnnotations[cmapi.IngressIssuerNameAnnotationKey] = vsCmSpec.Issuer
	}

	return ingLikeAnnotations, nil
}
