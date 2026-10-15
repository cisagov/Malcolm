# Deploying Malcolm on Azure Kubernetes Service (AKS)

This guide covers a deployment using the Kubernetes manifests shipped with
Malcolm, on an **existing AKS cluster**. It complements
[Deploying Malcolm with Kubernetes](kubernetes.md#Kubernetes). The
[Malcolm Helm chart](https://github.com/idaholab/Malcolm-Helm/) is also an
option, but the YAML examples below are for Malcolm's manifest-based deployment.

**Status:** The example manifests are statically validated, not tested against
an Azure subscription. Test the chosen AKS networking, storage, permissions,
and recovery process before deploying production data.

## 1. Check the cluster and access

Prerequisites:

- An AKS cluster with Linux worker nodes and sufficient CPU, memory and storage
  for your traffic volume and OpenSearch workload.
- Azure CLI and `kubectl` installed, an identity authorized to access the
  correct AKS cluster, and a locally checked-out Malcolm release.
- The Azure Files and Azure Disks CSI drivers. For NFS shares, arrange the
  required **Premium Azure Files storage, private network access, DNS, and
  worker-to-storage connectivity** before deploying. See Microsoft's
  [Azure Files CSI](https://learn.microsoft.com/en-us/azure/aks/azure-csi-files-storage-provision)
  and [AKS storage](https://learn.microsoft.com/en-us/azure/aks/concepts-storage)
  documentation.
- A backup and recovery plan for OpenSearch data, PCAPs, extracted files,
  configuration, and authentication secrets.

Run these commands from the root of the Malcolm checkout. Substitute your
resource group and cluster name; do not store kubeconfig or cloud credentials
inside the Git repository.

```bash
export RESOURCE_GROUP="your-aks-resource-group"
export AKS_CLUSTER="your-aks-cluster"
export MALCOLM_KUBECONFIG="$HOME/.kube/malcolm-aks.config"
mkdir -p "$HOME/.kube"
az account show --query "{subscription:id, name:name}" -o json
az aks get-credentials --resource-group "$RESOURCE_GROUP"   --name "$AKS_CLUSTER" --file "$MALCOLM_KUBECONFIG"
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" get nodes
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" get csidrivers
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" get storageclass
```

Confirm that the target subscription and cluster are correct before creating
resources. Expect `file.csi.azure.com` and `disk.csi.azure.com` among the
available CSI drivers. Existing clusters without the Files CSI driver may
require `az aks update --resource-group "$RESOURCE_GROUP" --name "$AKS_CLUSTER" --enable-file-driver`.

## 2. Configure persistent storage

Malcolm's pods require multiple persistent volume claims (PVCs), not just one.
The examples in this repository are:

- [AKS StorageClasses](../kubernetes/00-storageclass-aks.yml.example):
  `malcolm-azurefile-nfs` for shared NFS volumes and
  `malcolm-azuredisk` for OpenSearch's single-writer block storage.
- [AKS PVC definitions](../kubernetes/01-volumes-aks.yml.example):
  all eight claim names referenced by Malcolm's deployment manifests.

The NFS StorageClass uses Premium Azure Files; the disk class uses managed
Azure Disks. Both explicitly request `Retain` reclaim policy to avoid
automatically deleting the underlying storage when a PVC is deleted. Retained
volumes still require a deliberate, tested recovery/rebinding procedure.

**Review the provisioned sizes and resulting Azure costs before applying.**
Premium file shares have minimum size and networking requirements. The sample
is not a production capacity recommendation. OpenSearch's index volume is
`ReadWriteOnce`; sharing it across multiple OpenSearch writers would be unsafe.

First create the cluster-scoped storage classes:

```bash
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" apply   -f kubernetes/00-storageclass-aks.yml.example
```

Next copy the PVC example to the filename Malcolm expects, after checking
that an existing `01-volumes.yml` will not be overwritten:

```bash
test ! -e kubernetes/01-volumes.yml
cp kubernetes/01-volumes-aks.yml.example kubernetes/01-volumes.yml
```

Review the storage requests, namespace, class names, and permissions in the
copied manifest. The `.example` files are not auto-deployed; Malcolm reads the
`.yml` files under `kubernetes/` when starting. Do not copy the StorageClass
example to `00-storageclass.yml` because it has already been applied separately.

For existing production clusters, confirm that the selected CSI provisioners,
resource quotas, node network policies, mount permissions, and zone placement
match your environment. Azure Files NFS needs working private network access,
not merely the existence of the storage class.

## 3. Configure and start Malcolm

Use the same kubeconfig consistently for each command.

```bash
./scripts/configure -f "$MALCOLM_KUBECONFIG"
./scripts/auth_setup -f "$MALCOLM_KUBECONFIG"
./scripts/start -f "$MALCOLM_KUBECONFIG"
./scripts/status -f "$MALCOLM_KUBECONFIG"
```

Consult [Malcolm Kubernetes configuration](kubernetes.md#Config) and
[authentication setup](authsetup.md#AuthSetup). Do not regenerate
authentication certificates or secrets when upgrading an existing deployment
unless intentional.

To inspect the Kubernetes resources directly:

```bash
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm get pvc
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm get pods
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm get events   --sort-by=.lastTimestamp
```

All necessary PVCs should become `Bound`, and expected application pods should
be ready. Provisioning failures should be investigated before troubleshooting
application containers.

## 4. Access and network security

**Do not expose OpenSearch or Malcolm's ingestion services directly to the
public Internet.** For initial local troubleshooting through an authorized
AKS network, you can forward the Malcolm nginx-proxy service to your own
computer:

```bash
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm   port-forward service/nginx-proxy 8443:443
```

In a separate terminal, visit `https://localhost:8443/` and verify the
certificate as appropriate for your locally configured Malcolm instance.

For a permanent deployment, use an AKS-compatible ingress controller or
internal load balancer with managed TLS, restricted source networks, and
appropriate authentication. The example
[Traefik ingress](../kubernetes/99-ingress-traefik.yml.example) requires
Traefik and is **not** an automatically installed AKS ingress controller.
Do not simply expose every port from that example.

AKS also does not automatically provide host-interface packet capture of
all traffic traversing a virtual network. Plan PCAP uploads and external
log sources separately; see [Uploading PCAPs](upload.md) and
[Third-party logs](third-party-logs.md).

## 5. Troubleshooting, backups, and cleanup

If PVCs remain `Pending`:

```bash
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm describe   pvc opensearch-claim
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" -n malcolm describe   pvc pcap-claim
kubectl --kubeconfig "$MALCOLM_KUBECONFIG" get storageclass
```

Check Azure Files share provisioning, storage quotas, private DNS, networking,
managed identity permissions, worker availability zones, and disk scheduling.
Read the PVC's events to identify the exact CSI error.

Before changing storage classes or deleting any Kubernetes resources, take
and verify backups of data and credentials. A `Retain` reclaim policy protects
against automatic volume deletion, **not** against corrupt data or unintended
writes. Never delete the entire resource group as a routine application reset.

The AKS cluster and its persistent storage may continue accruing costs after
Malcolm's pods are stopped. Review the [Kubernetes operations guide](kubernetes.md#Running)
and Azure resources before cleanup.
