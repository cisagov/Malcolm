# <a name="Azure"></a>Deploying Malcolm on Azure Kubernetes Service (AKS)

This guide describes a straightforward Malcolm deployment on [Azure Kubernetes Service (AKS)](https://learn.microsoft.com/azure/aks/) using Malcolm's standard Kubernetes manifests. It complements the general [Kubernetes deployment documentation](kubernetes.md#Kubernetes).

## <a name="AzurePrerequisites"></a>Prerequisites

Install the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), `kubectl`, `git`, and [Helm](https://helm.sh/docs/intro/install/). Sign in with `az login` and select the Azure subscription that will host the cluster.

Size the cluster so its aggregate CPU, memory, and storage meet Malcolm's [recommended system requirements](system-requirements.md#SystemRequirements). The exact VM SKU and node count are deployment-specific.

The examples below use environment variables so resource names can be changed without editing every command:

```bash
export RESOURCE_GROUP=malcolm-rg
export AKS_CLUSTER=malcolm-aks
export LOCATION=eastus
export NODE_COUNT=3
export NODE_VM_SIZE=Standard_D8s_v5
export KUBECONFIG="$PWD/aks-kubeconfig"
```

Choose a `NODE_VM_SIZE` and `NODE_COUNT` appropriate for the expected workload and available quota.

## <a name="AzureCluster"></a>Create and connect to the AKS cluster

Create a resource group and AKS cluster:

```bash
az group create \
  --name "$RESOURCE_GROUP" \
  --location "$LOCATION"

az aks create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$AKS_CLUSTER" \
  --node-count "$NODE_COUNT" \
  --node-vm-size "$NODE_VM_SIZE" \
  --generate-ssh-keys
```

Download the cluster credentials into a dedicated kubeconfig file and verify connectivity:

```bash
az aks get-credentials \
  --resource-group "$RESOURCE_GROUP" \
  --name "$AKS_CLUSTER" \
  --file "$KUBECONFIG" \
  --overwrite-existing

kubectl --kubeconfig "$KUBECONFIG" get nodes -o wide
```

AKS clusters using CSI drivers provide built-in storage classes for Azure Files and Azure Disks. Verify that the storage classes used by the Malcolm example are available:

```bash
kubectl --kubeconfig "$KUBECONFIG" get storageclass \
  azurefile-csi-premium managed-csi-premium
```

## <a name="AzureStorage"></a>Configure persistent storage

Malcolm requires persistent volumes for configuration, PCAP, logs, extracted files, and OpenSearch data. Copy the AKS storage example into the active Kubernetes manifest name:

```bash
cp kubernetes/01-volumes-azure.yml.example kubernetes/01-volumes.yml
```

The example uses:

* `azurefile-csi-premium` for claims that may be mounted by multiple pods (`ReadWriteMany`)
* `managed-csi-premium` for OpenSearch data and snapshot claims (`ReadWriteOnce`)

The requested sizes mirror Malcolm's existing NFS volume example and should be adjusted for the deployment's retention and workload requirements before starting Malcolm.

## <a name="AzureIngress"></a>Install Traefik and configure ingress

Malcolm includes a Traefik `IngressRoute` example. Install Traefik with the entry points required by Malcolm:

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update

helm upgrade --install traefik traefik/traefik \
  --namespace traefik \
  --create-namespace \
  --kubeconfig "$KUBECONFIG" \
  --values kubernetes/traefik-values-azure.yml.example
```

Copy Malcolm's Traefik ingress example into the active ingress manifest name:

```bash
cp kubernetes/99-ingress-traefik.yml.example kubernetes/99-ingress.yml
```

The Azure Traefik values example exposes the web interface and Malcolm's optional forwarding/upload entry points through an Azure `LoadBalancer` service. To restrict exposure, edit the values file before installation and disable entry points that are not required.

## <a name="AzureMalcolm"></a>Configure and start Malcolm

Configure Malcolm using the AKS kubeconfig:

```bash
./scripts/configure -f "$KUBECONFIG"
./scripts/auth_setup -f "$KUBECONFIG"
```

Start the Kubernetes deployment:

```bash
./scripts/start -f "$KUBECONFIG"
```

Check Malcolm's status and the Traefik service:

```bash
./scripts/status -f "$KUBECONFIG"
kubectl --kubeconfig "$KUBECONFIG" -n traefik get service traefik
```

Once Azure assigns an external IP address to the Traefik service, browse to `https://<external-ip>/`. Malcolm uses a self-signed certificate by default unless [custom TLS certificates](authsetup.md#TLSCerts) have been configured.

## <a name="AzureCleanup"></a>Cleanup

Stop Malcolm before deleting the Azure resources if you no longer need the deployment:

```bash
./scripts/stop -f "$KUBECONFIG"
az group delete --name "$RESOURCE_GROUP"
```

Deleting the resource group removes the AKS cluster and Azure resources created in that resource group. Review the persistent storage and backup requirements before deleting it.
