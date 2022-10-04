/*
Copyright 2022.

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

package controllers

import (
	"context"
	"fmt"

	"github.com/theckman/go-securerandom"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	encryptionv1alpha1 "github.com/jobilla/secure-key-operator/api/v1alpha1"
)

// RandomStringReconciler reconciles a RandomString object
type RandomStringReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=crypto.jobilla.dev,resources=randomstrings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=crypto.jobilla.dev,resources=randomstrings/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=crypto.jobilla.dev,resources=randomstrings/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=list;watch;get;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the RandomString object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *RandomStringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	rs := &encryptionv1alpha1.RandomString{}
	if err := r.Client.Get(ctx, req.NamespacedName, rs); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	secret := &v1.Secret{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: rs.Spec.WriteSecretToRef.Name}, secret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}

		// at this point, we know the secret doesn't exist, so we'll create it
		secret.Name = rs.Spec.WriteSecretToRef.Name
		secret.Namespace = req.Namespace

		randomBytes := ""

		if rs.Spec.Format == "base64" || rs.Spec.Format == "base64prefixed" {
			randomBytes, err = securerandom.Base64OfBytes(rs.Spec.Length)
			if err != nil {
				return ctrl.Result{}, err
			}

			if rs.Spec.Format == "base64prefixed" {
				randomBytes = fmt.Sprintf("base64:%s", randomBytes)
			}
		} else {
			b, err := securerandom.Bytes(rs.Spec.Length)
			if err != nil {
				return ctrl.Result{}, err
			}

			randomBytes = string(b)
		}

		secret.StringData = map[string]string{}
		secret.StringData[rs.Spec.WriteSecretToRef.Key] = randomBytes
		if err := controllerutil.SetOwnerReference(rs, secret, r.Scheme); err != nil {
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, r.Client.Create(ctx, secret)
	}

	// the secret already exists, we need to check if anything changed

	// check if a secret already exists for the string
	// if it does, exit out; we don't want to make changes
	// if the secret ref changes, we will regenerate the key

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RandomStringReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&encryptionv1alpha1.RandomString{}).
		Complete(r)
}
