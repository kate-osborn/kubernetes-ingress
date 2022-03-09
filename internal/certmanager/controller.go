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
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/golang/glog"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	cm_clientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	cm_informers "github.com/jetstack/cert-manager/pkg/client/informers/externalversions"
	controllerpkg "github.com/jetstack/cert-manager/pkg/controller"
	conf_v1 "github.com/nginxinc/kubernetes-ingress/pkg/apis/configuration/v1"
	k8s_nginx "github.com/nginxinc/kubernetes-ingress/pkg/client/clientset/versioned"
	vsinformers "github.com/nginxinc/kubernetes-ingress/pkg/client/informers/externalversions"
	vslisters "github.com/nginxinc/kubernetes-ingress/pkg/client/listers/configuration/v1"
	kubeinformers "k8s.io/client-go/informers"
)

const (
	ControllerName = "vs-cm-shim"

	// resyncPeriod is set to 10 hours across cert-manager. These 10 hours come
	// from a discussion on the controller-runtime project that boils down to:
	// never change this without an explicit reason.
	// https://github.com/kubernetes-sigs/controller-runtime/pull/88#issuecomment-408500629
	resyncPeriod = 10 * time.Hour
)

type CmController struct {
	vsLister      vslisters.VirtualServerLister
	sync          SyncFn
    ctx           context.Context
	mustSync      []cache.InformerSynced
	queue         workqueue.RateLimitingInterface
}

type CmOpts struct {
	context    context.Context
	kubeConfig *rest.Config
	kubeClient kubernetes.Interface
	namespace  string
}

func (c *CmController) Register(ctx *controllerpkg.Context) (workqueue.RateLimitingInterface, []cache.InformerSynced, error) {
	handlers := createVirtualServerHandlers(c.queue)
	confClient, _ := k8s_nginx.NewForConfig(ctx.RESTConfig)

	sharedInformerFactory := vsinformers.NewSharedInformerFactoryWithOptions(confClient, resyncPeriod)
	informer := sharedInformerFactory.K8s().V1().VirtualServers().Informer()
	informer.AddEventHandler(handlers)
	c.vsLister = sharedInformerFactory.K8s().V1().VirtualServers().Lister()

	c.sync = SyncFnFor(ctx.Recorder, ctx.CMClient, ctx.SharedInformerFactory.Certmanager().V1().Certificates().Lister(), ctx.IngressShimOptions)

	// Even thought the VirtualServer controller already re-queues the VirtualServer after
	// creating a child Certificate, we still re-queue the VirtualServer when we
	// receive an "Add" event for the Certificate (the workqueue de-duplicates
	// keys, so we should not worry).
	//
	// Regarding "Update" events on Certificates, we need to requeue the parent
	// VirtualServer because we need to check if the Certificate is still up to date.
	//
	// Regarding "Deleted" events on Certificates, we requeue the parent VirtualServer
	// to immediately recreate the Certificate when the Certificate is deleted.
	ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().AddEventHandler(&controllerpkg.BlockingEventHandler{
		WorkFunc: certificateHandler(c.queue),
	})

	mustSync := []cache.InformerSynced{
		informer.HasSynced,
		ctx.SharedInformerFactory.Certmanager().V1().Certificates().Informer().HasSynced,
	}

	return c.queue, mustSync, nil
}

func (c *CmController) ProcessItem(ctx context.Context, key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		runtime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	crt, err := c.vsLister.VirtualServers(namespace).Get(name)
	if err != nil {
		if k8sErrors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("virtualServer '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	return c.sync(ctx, crt)
}

// Whenever a Certificate gets updated, added or deleted, we want to reconcile
// its parent VirtualServer. This parent VirtualServer is called "controller object". For
// example, the following Certificate "cert-1" is controlled by the VirtualServer
// "vs-1":
//
//     kind: Certificate
//     metadata:                                           Note that the owner
//       namespace: cert-1                                 reference does not
//       ownerReferences:                                  have a namespace,
//       - controller: true                                since owner refs
//         apiVersion: networking.x-k8s.io/v1alpha1        only work inside
//         kind: VirtualServer                                   the same namespace.
//         name: vs-1
//         blockOwnerDeletion: true
//         uid: 7d3897c2-ce27-4144-883a-e1b5f89bd65a
func certificateHandler(queue workqueue.RateLimitingInterface) func(obj interface{}) {
	return func(obj interface{}) {
		crt, ok := obj.(*cmapi.Certificate)
		if !ok {
			runtime.HandleError(fmt.Errorf("not a Certificate object: %#v", obj))
			return
		}

		ref := metav1.GetControllerOf(crt)
		if ref == nil {
			// No controller should care about orphans being deleted or
			// updated.
			return
		}

		// We don't check the apiVersion
		// because there is no chance that another object called "VirtualServer" be
		// the controller of a Certificate.
		if ref.Kind != "VirtualServer" {
			return
		}

		queue.Add(crt.Namespace + "/" + ref.Name)
	}
}

func createVirtualServerHandlers(queue workqueue.RateLimitingInterface) cache.ResourceEventHandlerFuncs {
	return cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			vs := obj.(*conf_v1.VirtualServer)
			queue.Add(vs)
		},
		DeleteFunc: func(obj interface{}) {
			vs, isVs := obj.(*conf_v1.VirtualServer)
			if !isVs {
				deletedState, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					runtime.HandleError(fmt.Errorf("received unexpected object: %#v", obj))
					return
				}
				vs, ok = deletedState.Obj.(*conf_v1.VirtualServer)
				if !ok {
					runtime.HandleError(fmt.Errorf("DeletedFinalStateUnknown contained non-VirtualServer object:: %#v", obj))
					return
				}
			}
			queue.Add(vs)
		},
		UpdateFunc: func(old, cur interface{}) {
			curVs := cur.(*conf_v1.VirtualServer)
			oldVs := old.(*conf_v1.VirtualServer)
			if !reflect.DeepEqual(oldVs.Spec.TLS.CertManager, curVs.Spec.TLS.CertManager) {
				queue.Add(curVs)
			}
		},
	}
}

func NewCmController(opts *CmOpts) *CmController {
	cm := &CmController{queue: workqueue.NewNamedRateLimitingQueue(controllerpkg.DefaultItemBasedRateLimiter(), ControllerName), ctx: opts.context}
	ctx := buildContext(opts)
	_, mustSync, _ := cm.Register(ctx)
	cm.mustSync = mustSync
	return cm
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *CmController) Run(workers int, stopCh <-chan struct{}) error {

	ctx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	glog.Info("starting cert manager control loop")
	// wait for all the informer caches we depend on are synced
	if !cache.WaitForCacheSync(stopCh, c.mustSync...) {
		return fmt.Errorf("error waiting for informer caches to sync")
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runWorker(ctx)
		}()
	}

	<-stopCh
	glog.Info("shutting down queue as workqueue signaled shutdown")
	c.queue.ShutDown()
	glog.Info("waiting for workers to exit...")
	wg.Wait()
	glog.Info("workers exited")
	return nil
}

// runWorker is a long-running function that will continually call the
// processItem function in order to read and process a message on the
// workqueue.
func (c *CmController) runWorker(ctx context.Context) {
	for {
		obj, shutdown := c.queue.Get()
		if shutdown {
			break
		}

		var key string
		// use an inlined function so we can use defer
		func() {
			defer c.queue.Done(obj)
			var ok bool
			if key, ok = obj.(string); !ok {
				return
			}
			
			err := c.ProcessItem(ctx, key)
			if err != nil {
				glog.Error(err, "re-queuing item due to error processing")
				c.queue.AddRateLimited(obj)
				return
			}
			glog.Info("finished processing work item")
			c.queue.Forget(obj)
		}()
	}
}

func buildContext(opts *CmOpts) *controllerpkg.Context {

	// Create a cert-manager api client
	intcl := cm_clientset.New(opts.kubeClient.CoreV1().RESTClient())

	sharedInformerFactory := cm_informers.NewSharedInformerFactoryWithOptions(intcl, resyncPeriod, cm_informers.WithNamespace(opts.namespace))
	kubeSharedInformerFactory := kubeinformers.NewSharedInformerFactoryWithOptions(opts.kubeClient, resyncPeriod, kubeinformers.WithNamespace(opts.namespace))

	return &controllerpkg.Context{
		RootContext:               opts.context,
		StopCh:                    opts.context.Done(),
		RESTConfig:                opts.kubeConfig,
		Client:                    opts.kubeClient,
		CMClient:                  intcl,
		DiscoveryClient:           opts.kubeClient.Discovery(),
		KubeSharedInformerFactory: kubeSharedInformerFactory,
		SharedInformerFactory:     sharedInformerFactory,
		IngressShimOptions:        controllerpkg.IngressShimOptions{},
	}
}

func BuildOpts(ctx context.Context, kc *rest.Config, cl kubernetes.Interface, ns string) *CmOpts {
	return &CmOpts{
		context:    ctx,
		kubeClient: cl,
		kubeConfig: kc,
		namespace:  ns,
	}
}
