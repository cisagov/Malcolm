# <a name="Kubernetes"></a>Deploying Malcolm with Kubernetes

* [Deploying Malcolm with Kubernetes](#Kubernetes)
    - [System](#System)
        + [Ingress Controllers](#Ingress)
            * [Traefik Ingress Controller](#IngressTraefik)
        + [Kubernetes Provider Settings](#Limits)
* [Configuration](#Config)
    - [OpenSearch and Elasticsearch Instances](#OpenSearchInstances)
    - [PersistentVolumeClaim Definitions](#PVC)
* [Running Malcolm](#Running)
* [Deployment Example](#Example)
* [Future Enhancements](#Future)
    - [Live Traffic Analysis](#FutureLiveCap)
    - [Horizontal Scaling](#FutureScaleOut)
    - [Helm Chart](#FutureHelmChart)
* [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](aws.md#AWSEKSAuto)

This document assumes good working knowledge of Kubernetes (K8s). The comprehensive [Kubernetes documentation](https://kubernetes.io/docs/home/) is a good place to go for more information about Kubernetes.

This document describes deploying Malcolm on Kubernetes using the standard [Kubernetes manifests]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/). The official [Malcolm Helm chart](https://github.com/idaholab/Malcolm-Helm/) is now stable and may be preferable for production deployments, as it better leverages Kubernetes scalability features. Review the Malcolm-Helm documentation to choose the deployment method that best fits your environment.

## <a name="System"></a> System

### <a name="Ingress"></a> Ingress Controllers

There exist a variety of ingress controllers for Kubernetes suitable for different Kubernetes providers and environments. A few sample manifests for ingress controllers can be found in Malcolm's [`kubernetes`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/) directory, prefixed with `99-ingress-…`:

* [`kubernetes/99-ingress-traefik.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-traefik.yml.example) - an example ingress manifest for Malcolm using the [Traefik ingress controller for Kubernetes](https://doc.traefik.io/traefik/reference/install-configuration/providers/kubernetes/kubernetes-ingress/). The Traefik controller has been used internally on self-hosted Kubernetes clusters during Malcolm's development and testing.
* [`kubernetes/99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example) - an example ingress manifest for Malcolm using the [AWS Load Balancer (ALB) Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/#aws-load-balancer-controller). Users likely will prefer to use ALB to [deploy Malcolm on Amazon Elastic Kubernetes Service (EKS)](aws.md#AWSEKSAuto).

Before [running](#Running) Malcolm copy one of the `99-ingress-…` files to `99-ingress.yml` as a starting point to define the ingress, or define a custom manifest file and save it as `99-ingress.yml`.

#### <a name="IngressTraefik"></a> Traefik Ingress Controller

In order to [use the Traefik ingress controller with Malcolm]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-traefik.yml.example), it must first be installed. Consult your Kubernetes platform's documentation for how to install Traefik on Kubernetes, or read [Getting Started with Kubernetes and Traefik¶](https://doc.traefik.io/traefik/getting-started/kubernetes/).

The Vagrant-based [deployment example](#Example) below illustrates deploying Malcolm with the Traefik ingress controller, including installing Traefik via its Helm chart (search for `HelmChart` in [kubernetes/vagrant/Vagrantfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile)) and exposing Malcolm service ports via `NodePort` (see also [`kubernetes/99-ingress-traefik.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-traefik.yml.example)).

### <a name="Limits"></a> Kubernetes Provider Settings

OpenSearch has some [important settings](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/#important-settings) that must be present on its underlying Linux system. How these settings are configured depends largely on the underlying host(s) running Kubernetes, and how Kubernetes is installed or the cloud provider on which it is running. Consult the operating system or cloud provider documentation for how to configure these settings.

Settings that likely need to be changed in the underlying host running Kubernetes include:

* System settings (e.g., under `/etc/sysctl.d/`)
        ```
        # the maximum number of memory map areas a process may have
        vm.max_map_count=262144
        ```
* System limits (e.g., in `/etc/security/limits.d/limits.conf`)
        ```
        + soft nofile 65535
        + hard nofile 65535
        + soft memlock unlimited
        + hard memlock unlimited
        + soft nproc 262144
        + hard nproc 524288
        + soft core 0
        + hard core 0
        ```

## <a name="Config"></a> Configuration

The steps to configure and tune Malcolm for a Kubernetes deployment are [very similar](malcolm-config.md#ConfigAndTuning) to those for a Docker-based deployment. Both methods use [environment variable files](malcolm-config.md#MalcolmConfigEnvVars) for Malcolm's runtime configuration.

Malcolm's configuration and runtime scripts (e.g., `./scripts/configure`, `./scripts/auth_setup`, `./scripts/start`, etc.) are used for both Docker- and Kubernetes-based deployments. In order to indicate to these scripts that Kubernetes is being used rather than `docker compose`, users can provide the script with the [kubeconfig file](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) used to communicate with the API server of the Kubernetes cluster (e.g., `./scripts/configure -f k3s.yaml` or `./scripts/start -f kubeconfig.yaml`, etc.). The scripts will detect whether the YAML file specified is a kubeconfig file or a Docker compose file and act accordingly.

Run `./scripts/configure` to configure Malcolm. For an in-depth treatment of the configuration options, see the **Malcolm Configuration Menu Items** section in **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems)**. Users will need to run [`./scripts/auth_setup`](authsetup.md#AuthSetup) to configure authentication.

### <a name="OpenSearchInstances"></a> OpenSearch and Elasticsearch Instances

While Malcolm can manage its own single-node OpenSearch instance as part of its Kubernetes deployment, users may want to use an existing multi-node OpenSearch or Elasticsearch cluster hosted on Kubernetes or some other provider (see, for example, ["Setup OpenSearch multi-node cluster on Kubernetes using Helm Charts"](https://opensearch.org/blog/setup-multinode-cluster-kubernetes/) on the OpenSearch blog and ["OpenSearch Kubernetes Operator"](https://opensearch.org/docs/latest/tools/k8s-operator/) in the OpenSearch documentation). Review Malcolm's documentation on [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance) to configure a Malcolm deployment to use an OpenSearch or Elasticsearch cluster.

### <a name="PVC"></a> PersistentVolumeClaim Definitions

Malcolm requires persistent [storage](https://kubernetes.io/docs/concepts/storage/) to be configured for its configuration and data files. There are various implementations for provisioning PersistentVolume resources using [storage classes](https://kubernetes.io/docs/concepts/storage/storage-classes/). Regardless of the types of storage underlying the PersistentVolumes, Malcolm requires the following PersistentVolumeClaims to be defined in the `malcolm` namespace:

* `config-claim` - storage for configuration files
* `opensearch-backup-claim` - storage for OpenSearch snapshots (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `opensearch-claim` - storage for OpenSearch indices (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `pcap-claim` - storage for PCAP artifacts
* `runtime-logs-claim` - storage for runtime logs for some containers (e.g., nginx, Arkime)
* `suricata-claim` - storage for Suricata logs
* `zeek-claim` - storage for Zeek logs and files extracted by Zeek

An example of how these PersistentVolume and PersistentVolumeClaim objects could be defined using NFS can be found in the [kubernetes/01-volumes-nfs.yml.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-nfs.yml.example) manifest file, used in conjunction with the NFS server in the [vagrant-based deployment example](#Example) ([kubernetes/vagrant/Vagrantfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile)). Before [running](#Running) Malcolm, copy `01-volumes-nfs.yml.example` to `01-volumes.yml` and modify (or replace) its contents to define the PersistentVolumeClaim objects configured for your own NFS server IP address and exported paths.

Attempting to start Malcolm without these PersistentVolumeClaims defined in a YAML file in Malcolm's `./kubernetes/` directory will result in an error like this:

```
$ ./scripts/start -f /path/to/kubeconfig.yml
Exception: Storage objects required by Malcolm are not defined in /home/user/Malcolm/kubernetes: {'PersistentVolumeClaim': ['pcap-claim', 'zeek-claim', 'suricata-claim', 'config-claim', 'runtime-logs-claim', 'opensearch-claim', 'opensearch-backup-claim']}
```

## <a name="Running"></a> Running Malcolm

After [configuring](#Config) Malcolm, use the `./scripts/start` script to create the Malcolm Kubernetes deployment, providing the kubeconfig file with the `-f`/`--file` argument:

```
$ ./scripts/start -f /path/to/kubeconfig.yml
```

The Kubernetes resources under the `malcolm` namespace (its pods, storage volumes, containers, etc.) will be initialized and started using the [Kubernetes API](https://kubernetes.io/docs/concepts/overview/kubernetes-api/), including:

* creating [ConfigMap objects](https://kubernetes.io/docs/concepts/configuration/configmap/) and [Secret objects](https://kubernetes.io/docs/concepts/configuration/secret/) from Malcolm's [environment variable files](malcolm-config.md#MalcolmConfigEnvVars)
* creating [ConfigMap objects](https://kubernetes.io/docs/concepts/configuration/configmap/) and [Secret objects](https://kubernetes.io/docs/concepts/configuration/secret/) from other configuration files stored locally below the Malcolm directory
* deploying the objects defined in the [Kubernetes manifests]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/) in `./kubernetes`

After a few moments, users can check the status of the deployment:

```
$ ./scripts/status -f /path/to/kubeconfig.yml
Node Name        | Hostname         | IP              | Provider ID      | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods |
-----------------+------------------+-----------------+------------------+---------------+-----------+-----------+-------------+--------------+--------------+---------------+--------------|
malcolm-462510   | malcolm-462510   | 192.168.122.37  | malcolm-462510   | k3s           | 16000m    | 17.57m    | 0.11%       | 23.49Gi      | 476.8Mi      | 58.37Gi       | 1            |
malcolm-463728   | malcolm-463728   | 192.168.122.40  | malcolm-463728   | k3s           | 24000m    | 439.55m   | 1.83%       | 94.33Gi      | 6.18Gi       | 109.44Gi      | 6            |
malcolm-651135   | malcolm-651135   | 192.168.122.226 | malcolm-651135   | k3s           | 48000m    | 3525.39m  | 7.34%       | 62.79Gi      | 7.58Gi       | 91.11Gi       | 10           |
malcolm-651420   | malcolm-651420   | 192.168.122.30  | malcolm-651420   | k3s           | 40000m    | 384.83m   | 0.96%       | 125.79Gi     | 20.68Gi      | 91.11Gi       | 4            |
malcolm-651490   | malcolm-651490   | 192.168.122.227 | malcolm-651490   | k3s           | 32000m    | 620.71m   | 1.94%       | 47.04Gi      | 2.88Gi       | 182.28Gi      | 5            |
malcolm-651492   | malcolm-651492   | 192.168.122.44  | malcolm-651492   | k3s           | 32000m    | 669.12m   | 2.09%       | 62.79Gi      | 2.09Gi       | 109.44Gi      | 6            |
malcolm-651493   | malcolm-651493   | 192.168.122.222 | malcolm-651493   | k3s           | 32000m    | 3609.89m  | 11.28%      | 62.79Gi      | 6.22Gi       | 182.28Gi      | 6            |
malcolm-651525   | malcolm-651525   | 192.168.122.221 | malcolm-651525   | k3s           | 16000m    | 122.93m   | 0.77%       | 46.83Gi      | 1.96Gi       | 182.28Gi      | 3            |
malcolm-655079   | malcolm-655079   | 192.168.122.32  | malcolm-655079   | k3s           | 24000m    | 237.0m    | 0.99%       | 94.32Gi      | 7.49Gi       | 109.44Gi      | 4            |
malcolm-655103   | malcolm-655103   | 192.168.122.36  | malcolm-655103   | k3s           | 24000m    | 222.27m   | 0.93%       | 94.32Gi      | 1.24Gi       | 109.44Gi      | 4            |
malcolm-655119   | malcolm-655119   | 192.168.122.43  | malcolm-655119   | k3s           | 24000m    | 1098.66m  | 4.58%       | 94.32Gi      | 18.92Gi      | 109.44Gi      | 5            |
malcolm-655152   | malcolm-655152   | 192.168.122.46  | malcolm-655152   | k3s           | 12000m    | 67.06m    | 0.56%       | 46.82Gi      | 689.14Mi     | 3665.02Gi     | 2            |
malcolm-655153   | malcolm-655153   | 192.168.122.34  | malcolm-655153   | k3s           | 12000m    | 85.8m     | 0.71%       | 46.82Gi      | 1.05Gi       | 455.95Gi      | 4            |
malcolm-655154   | malcolm-655154   | 192.168.122.38  | malcolm-655154   | k3s           | 12000m    | 76.03m    | 0.63%       | 46.82Gi      | 2.01Gi       | 109.44Gi      | 3            |
malcolm-655155   | malcolm-655155   | 192.168.122.42  | malcolm-655155   | k3s           | 12000m    | 40.7m     | 0.34%       | 46.82Gi      | 698.82Mi     | 109.44Gi      | 3            |
malcolm-655160   | malcolm-655160   | 192.168.122.35  | malcolm-655160   | k3s           | 12000m    | 22.76m    | 0.19%       | 46.82Gi      | 582.74Mi     | 109.44Gi      | 2            |
malcolm-673112   | malcolm-673112   | 192.168.122.41  | malcolm-673112   | k3s           | 12000m    | 24.96m    | 0.21%       | 30.72Gi      | 532.43Mi     | 455.95Gi      | 2            |
malcolm-681270   | malcolm-681270   | 192.168.122.47  | malcolm-681270   | k3s           | 12000m    | 70.45m    | 0.59%       | 30.72Gi      | 596.16Mi     | 455.95Gi      | 2            |

Pod Name                                      | State   | Pod IP       | Pod Kind   | Worker Node      | CPU Usage | Memory Usage | Container Name:Restarts       | Container Image                                    |
----------------------------------------------+---------+--------------+------------+------------------+-----------+--------------+-------------------------------+----------------------------------------------------|
api-deployment-7fff7bf884-84prz               | Running | 10.42.2.226  | ReplicaSet | malcolm-651525   | 0.12m     | 68.89Mi      | api-container:0               | ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}                   |
arkime-deployment-68946dffcb-fx8nl            | Running | 10.42.13.42  | ReplicaSet | malcolm-651490   | 309.86m   | 1.01Gi       | arkime-container:0            | ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}                |
dashboards-deployment-6456f67fb4-jhnqf        | Running | 10.42.11.184 | ReplicaSet | malcolm-463728   | 85.4m     | 215.95Mi     | dashboards-container:0        | ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}            |
dashboards-helper-deployment-7d5d8c5ddf-tphbx | Running | 10.42.17.23  | ReplicaSet | malcolm-655152   | 8.56m     | 47.26Mi      | dashboards-helper-container:0 | ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}     |
filebeat-deployment-855578fd56-wxz5t          | Running | 10.42.16.223 | ReplicaSet | malcolm-651135   | 5.77m     | 278.45Mi     | filebeat-container:0          | ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}          |
filescan-deployment-7b675999dd-m7sx8          | Running | 10.42.2.227  | ReplicaSet | malcolm-651525   | 4.32m     | 204.33Mi     | filescan-container:0          | ghcr.io/idaholab/malcolm/filescan:{{ site.malcolm.version }}              |
freq-deployment-5dbf7fd958-xdm4j              | Running | 10.42.9.23   | ReplicaSet | malcolm-655155   | 1.13m     | 36.59Mi      | freq-container:0              | ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}                  |
htadmin-deployment-6779876475-h5wwh           | Running | 10.42.10.48  | ReplicaSet | malcolm-651493   | 0.26m     | 43.36Mi      | htadmin-container:0           | ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}               |
keycloak-deployment-7fd4bdff5c-fkzxs          | Running | 10.42.9.24   | ReplicaSet | malcolm-655155   | 0.03m     | 11.07Mi      | keycloak-container:0          | ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}              |
logstash-deployment-5bbcc5b775-bjk59          | Running | 10.42.11.185 | ReplicaSet | malcolm-463728   | 68.84m    | 3.97Gi       | logstash-container:0          | ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}          |
netbox-deployment-987476c89-6vznb             | Running | 10.42.16.224 | ReplicaSet | malcolm-651135   | 428.2m    | 1.09Gi       | netbox-container:0            | ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}                |
nginx-proxy-deployment-6d9b9858fd-q9w5z       | Running | 10.42.3.140  | ReplicaSet | malcolm-655079   | 13.07m    | 25.78Mi      | nginx-proxy-container:0       | ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}           |
opensearch-deployment-6c546f45b9-n4czl        | Running | 10.42.7.165  | ReplicaSet | malcolm-655119   | 887.36m   | 17.8Gi       | opensearch-container:0        | ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}            |
pcap-monitor-deployment-66dbd9c68f-22tkm      | Running | 10.42.10.46  | ReplicaSet | malcolm-651493   | 183.31m   | 867.33Mi     | pcap-monitor-container:0      | ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}          |
postgres-deployment-5c78f478fb-nl4zn          | Running | 10.42.15.210 | ReplicaSet | malcolm-651492   | 472.87m   | 85.33Mi      | postgres-container:0          | ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}            |
valkey-cache-deployment-5c776698fc-dvbp2      | Running | 10.42.5.20   | ReplicaSet | malcolm-655154   | 9.58m     | 10.18Mi      | valkey-cache-container:0      | ghcr.io/idaholab/malcolm/valkey:{{ site.malcolm.version }}                |
valkey-deployment-75486865c5-4xscs           | Running | 10.42.15.209 | ReplicaSet | malcolm-651492   | 9.66m     | 10.04Mi      | valkey-container:0            | ghcr.io/idaholab/malcolm/valkey:{{ site.malcolm.version }}                |
strelka-backend-deployment-6dcf7ccdcc-xjbxx   | Running | 10.42.5.21   | ReplicaSet | malcolm-655154   | 4.72m     | 1.18Gi       | strelka-backend-container:0   | ghcr.io/idaholab/malcolm/strelka-backend:{{ site.malcolm.version }}       |
strelka-frontend-deployment-6988c75f8c-gmf8c  | Running | 10.42.6.23   | ReplicaSet | malcolm-655160   | 0.03m     | 8.02Mi       | strelka-frontend-container:0  | ghcr.io/idaholab/malcolm/strelka-frontend:{{ site.malcolm.version }}      |
strelka-manager-deployment-f578ccc7-2vw7l     | Running | 10.42.12.15  | ReplicaSet | malcolm-681270   | 2.41m     | 7.57Mi       | strelka-manager-container:0   | ghcr.io/idaholab/malcolm/strelka-manager:{{ site.malcolm.version }}       |
suricata-offline-deployment-86d4796bf7-wpzq5  | Running | 10.42.16.222 | ReplicaSet | malcolm-651135   | 2882.76m  | 4.11Gi       | suricata-offline-container:0  | ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}              |
upload-deployment-7d8886d86b-qnncd            | Running | 10.42.4.174  | ReplicaSet | malcolm-655103   | 78.27m    | 226.11Mi     | upload-container:0            | ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}           |
zeek-offline-deployment-fb7847b9b-jvtcj       | Running | 10.42.10.47  | ReplicaSet | malcolm-651493   | 3016.28m  | 3.14Gi       | zeek-offline-container:0      | ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}                  |
```

The other control scripts (`stop`, `restart`, `logs`, etc.) work in a similar manner as in a Docker-based deployment. One notable difference is the `wipe` script: data on PersistentVolume storage cannot be deleted by `wipe`. It must be deleted manually on the storage media underlying the PersistentVolumes.

Malcolm's control scripts require the [official Python 3 client library for Kubernetes](https://github.com/kubernetes-client/python) to configure and run Malcolm with Kubernetes. It is also recommended to install **[stern](https://github.com/stern/stern)**, which is used by the `./scripts/logs` script to tail Malcolm's container logs.

# <a name="Example"></a> Deployment Example

Here is a basic step-by-step example illustrating how to deploy Malcolm with Kubernetes. For the sake of simplicity, this example uses Vagrant: see [kubernetes/vagrant/Vagrantfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile) to create a virtualized Kubernetes cluster with a built-in NFS server for persistent storage. To follow this example, you'll need to download or copy the contents of [kubernetes/vagrant/]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant) from the Malcolm source code to a local directory. This example also assumes users have downloaded and extracted the [release tarball]({{ site.github.repository_url }}/releases/latest) or used `./scripts/malcolm_appliance_packager.sh` to package up the files needed to run Malcolm.

First, bring up the virtualized Kubernetes cluster and run the commands provided at the end of that process to retrieve the kubeconfig file, and create the [NFS PersistentVolumeClaims](#PVC) and [ingress controller](#IngressTraefik) based on the examples provided:

```bash
$ cd kubernetes/vagrant 

$ vagrant up
Bringing machine 'Malcolm-K8S' up with 'libvirt' provider...
…
Malcolm-K8S: Waiting for Traefik ingress controller...
Malcolm-K8S: Traefik ingress controller is ready
Malcolm-K8S: 
Malcolm-K8S: To SSH into the virtual machine, run:  vagrant ssh
Malcolm-K8S: To retrieve kubeconfig file, run:  vagrant ssh -c 'cat /home/vagrant/.kube/config' >./kubeconfig && sed -i 's/127.0.0.1/192.168.121.239/g' ./kubeconfig
Malcolm-K8S: 
Malcolm-K8S: To populate NFS volumes manifest, run: sed -e 's/^\([[:space:]]*server:[[:space:]]*\).*/\1192.168.121.239/' -e 's|/malcolm/|/mnt/vdb/nfs-export/malcolm/|g' ../01-volumes-nfs.yml.example >../01-volumes-nfs-vagrant.yml
Malcolm-K8S: 
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/config            192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/filescan-logs     192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/opensearch        192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/opensearch-backup 192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/pcap              192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/runtime-logs      192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/suricata-logs     192.168.121.239/24
Malcolm-K8S: /mnt/vdb/nfs-export/malcolm/zeek-logs         192.168.121.239/24

$ vagrant ssh -c 'cat /home/vagrant/.kube/config' >./kubeconfig && sed -i 's/127.0.0.1/192.168.121.239/g' ./kubeconfig

$ sed -e 's/^\([[:space:]]*server:[[:space:]]*\).*/\1192.168.121.239/' \
      -e 's|/malcolm/|/mnt/vdb/nfs-export/malcolm/|g' \
    ../01-volumes-nfs.yml.example > ../01-volumes-nfs-vagrant.yml 

$ cp ../99-ingress-traefik.yml.example ../99-ingress.yml

$ KUBECONFIG=kubeconfig kubectl get nodes
NAME        STATUS   ROLES                AGE     VERSION
debian-13   Ready    control-plane,etcd   6m58s   v1.35.3+rke2r3

$ cd ../../
```

Next, ensure the Malcolm source code (from the release tarball or git repository working copy) is present:


```bash
$ ls -l
total 45,056
drwxr-xr-x 2 user user  4,096 Apr 24 14:35 config
drwxr-xr-x 3 user user     19 Apr 24 14:35 filebeat
drwxr-xr-x 2 user user      6 Apr 24 14:35 htadmin
drwxr-xr-x 3 user user  4,096 Apr 24 14:39 kubernetes
drwxr-xr-x 4 user user     31 Apr 24 14:35 logstash
drwxr-xr-x 6 user user     62 Apr 24 14:35 netbox
drwxr-xr-x 4 user user     35 Apr 24 14:35 nginx
drwxr-xr-x 3 user user     19 Apr 24 14:35 opensearch
drwxr-xr-x 2 user user      6 Apr 24 14:35 opensearch-backup
drwxr-xr-x 4 user user     37 Apr 24 14:35 pcap
drwxr-xr-x 2 user user  4,096 Apr 24 14:35 scripts
drwxr-xr-x 3 user user     19 Apr 24 14:35 suricata
drwxr-xr-x 3 user user     18 Apr 24 14:35 suricata-logs
drwxr-xr-x 3 user user     19 Apr 24 14:35 yara
drwxr-xr-x 3 user user     19 Apr 24 14:35 zeek
drwxr-xr-x 7 user user     85 Apr 24 14:35 zeek-logs
-rw-r--r-- 1 user user 18,761 Apr 24 14:35 docker-compose.yml
-rw-r--r-- 1 user user  3,453 Apr 24 14:35 README.md
```

Even before starting Malcolm, the `status` script can verify communication with the Kubernetes cluster:

```bash
$ ./scripts/status -f ./kubernetes/vagrant/kubeconfig 
Node Name | Hostname  | IP              | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods | 
----------+-----------+-----------------+-------------+---------------+-----------+-----------+-------------+--------------+--------------+---------------+--------------|
debian-13 | debian-13 | 192.168.121.239 | debian-13   | rke2          | 8000m     | 942.81m   | 11.79%      | 31.35Gi      | 2.31Gi       | 58.8Gi        | 44           | 

Pod Name | State | Pod IP | Pod Kind | Worker Node | CPU Usage | Memory Usage | Container Name:Restarts | Container Image | 
---------+-------+--------+----------+-------------+-----------+--------------+-------------------------+-----------------|
```

Run `./scripts/configure` to configure Malcolm. For an in-depth treatment of the configuration options, see the **Malcolm Configuration Menu Items** section in **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems)**.:

```
$ ./scripts/configure -f ./kubernetes/vagrant/kubeconfig

--- Malcolm Configuration Menu ---
Select an item number to configure, or an action:
├── 1. Container Runtime (current: kubernetes)
│   ├── 2. Process Group ID (current: 1000)
│   └── 3. Process User ID (current: 1000)
├── 4. Run Profile (current: malcolm)
│   ├── 5. Dark Mode for Dashboards (current: Yes)
│   ├── 6. Extra Tags (current: [])
│   ├── 7. Forward Logs to Remote Secondary Store (current: No)
│   ├── 8. Logstash Memory (current: 2500m)
│   ├── 9. Logstash Workers (per pipeline) (current: 2)
│   ├── 10. OpenSearch Memory (current: 16g)
│   └── 11. Primary Document Store (current: opensearch-local)
├── 12. Require HTTPS Connections (current: Yes)
├── 13. IPv4 for nginx Resolver Directive (current: Yes)
├── 14. IPv6 for nginx Resolver Directive (current: No)
├── 15. Clean Up Artifacts (current: No)
├── 16. Enable Arkime Index Management (current: No)
├── 17. Enable Arkime Analysis (current: Yes)
│   ├── 18. Allow Arkime WISE Configuration (current: No)
│   └── 19. Enable Arkime WISE (current: Yes)
├── 20. Enable Suricata Analysis (current: Yes)
│   └── 21. Enable Suricata Rule Updates (current: No)
├── 22. Enable Zeek Analysis (current: Yes)
│   ├── 23. Enable Zeek ICS/OT Analyzers (current: Yes)
│   │   └── 24. Enable Zeek ICS "Best Guess" (current: Yes)
│   ├── 25. File Extraction Mode (current: interesting)
│   │   ├── 26. Extracted File Percent Threshold (current: 0)
│   │   ├── 27. Extracted File Size Threshold (current: 1TB)
│   │   ├── 28. File Preservation (current: quarantined)
│   │   ├── 29. File scanning workers (current: 1)
│   │   ├── 30. Preserved Files HTTP Server (current: Yes)
│   │   │   ├── 31. Downloaded Preserved File Password (current: ********)
│   │   │   └── 32. Zip Downloads (current: Yes)
│   │   ├── 33. Scan with Strelka (current: Yes)
│   │   └── 34. Update Scan Rules (current: No)
│   └── 35. Use Threat Feeds for Zeek Intelligence (current: Yes)
│       ├── 36. Cron Expression for Threat Feed Updates (current: 0 0 * * *)
│       ├── 37. Intel::item_expiration Timeout (current: -1min)
│       ├── 38. Pull Threat Intelligence Feeds on Startup (current: Yes)
│       ├── 39. Threat Indicator "Since" Period (current: 24 hours ago)
│       ├── 40. Use Intel on Live Traffic (current: Yes)
│       └── 41. Use Intel on Uploaded PCAP (current: Yes)
├── 42. Enrich with Reverse DNS Lookups (current: No)
├── 43. Enrich with Manufacturer (OUI) Lookups (current: Yes)
├── 44. Enrich with Frequency Scoring (current: Yes)
├── 45. NetBox Mode (current: Local)
│   ├── 46. Auto-Create Subnet Prefixes (current: Yes)
│   ├── 47. Auto-Populate NetBox Inventory (current: Yes)
│   ├── 48. NetBox Enrichment (current: Yes)
│   ├── 49. NetBox IP Autopopulation Filter (current: empty)
│   └── 50. NetBox Site Name (current: Malcolm)
├── 51. Expose Malcolm Service Ports (current: Yes)
│   └── 52. Expose Filebeat TCP (current: Yes)
│       └── 53. Use Filebeat TCP Listener Defaults (current: Yes)
├── 54. Network Traffic Node Name (current: vagrant)
└── 55. Capture Live Network Traffic (current: Yes)
    ├── 56. Analyze Live Traffic with Suricata (current: Yes)
    ├── 57. Analyze Live Traffic with Zeek (current: Yes)
    ├── 58. Capture Filter (current: empty)
    ├── 59. Capture Interface(s) (current: eth0)
    ├── 60. Capture Live Traffic with netsniff-ng (current: Yes)
    ├── 61. Capture Live Traffic with tcpdump (current: No)
    ├── 62. Gather Traffic Capture Statistics (current: Yes)
    └── 63. Optimize Interface Settings for Capture (current: Yes)

--- Actions ---
  s. Save and Continue
  w. Where Is...? (search for settings)
  x. Exit Installer
---------------------------------

Enter item number or action: s

============================================================
FINAL CONFIGURATION SUMMARY
============================================================
Configuration Only                                : Yes
Configuration Directory                           : /home/tlacuache/tmp/Malcolm/config
Container Runtime                                 : kubernetes
Run Profile                                       : malcolm
Process UID/GID                                   : 1000/1000
HTTPS/SSL                                         : Yes
Node Name                                         : vagrant
Logstash Workers (per pipeline)                   : 2
Logstash Memory                                   : 2500m
OpenSearch Memory                                 : 16g
Enable Zeek ICS/OT Analyzers                      : Yes
File Extraction Mode                              : interesting
Extracted File Size Threshold                     : 1TB
Downloaded Preserved File Password                : ********
Zip Downloads                                     : Yes
Auto-Create Subnet Prefixes                       : Yes
Auto-Populate NetBox Inventory                    : Yes
NetBox Site Name                                  : Malcolm
Expose Malcolm Service Ports                      : Yes
Capture Live Network Traffic                      : Yes
Capture Interface(s)                              : eth0
============================================================

Proceed using the above configuration? (y / N): y

```

Run `./scripts/auth_setup` and answer the questions to [configure authentication](authsetup.md#AuthSetup):

```
$ ./scripts/auth_setup -f ./kubernetes/vagrant/kubeconfig
…

1: all - Configure all authentication-related settings
2: method - Select authentication method (currently "basic")
3: admin - Store administrator username/password for basic HTTP authentication
4: webcerts - (Re)generate self-signed certificates for HTTPS access
5: fwcerts - (Re)generate self-signed certificates for a remote log forwarder
6: keycloak - Configure Keycloak
7: remoteos - Configure remote primary or secondary OpenSearch/Elasticsearch instance
8: email - Store username/password for OpenSearch Alerting email sender account
9: netbox - (Re)generate internal passwords for NetBox
10: keycloakdb - (Re)generate internal passwords for Keycloak's PostgreSQL database
11: postgres - (Re)generate internal superuser passwords for PostgreSQL
12: valkey - (Re)generate internal passwords for Valkey
13: arkime - Store password hash secret for Arkime viewer cluster
14: txfwcerts - Transfer self-signed client certificates to a remote log forwarder
Configure Authentication (all): 1

Select authentication method (currently "basic")? (Y / n): y
1: basic - Use basic HTTP authentication
2: ldap - Use Lightweight Directory Access Protocol (LDAP) for authentication
3: keycloak - Use embedded Keycloak for authentication
4: keycloak_remote - Use remote Keycloak for authentication
5: no_authentication - Disable authentication
Select authentication method (basic): 1

Store administrator username/password for basic HTTP authentication? (Y / n): y

Administrator username (between 4 and 32 characters; alphanumeric, _, -, and . allowed): analyst
analyst password  (between 8 and 128 characters):
analyst password (again):

(Re)generate self-signed certificates for HTTPS access? (Y / n): y

(Re)generate self-signed certificates for a remote log forwarder? (Y / n): y

Configure Keycloak? (Y / n): n

Configure remote primary or secondary OpenSearch/Elasticsearch instance? (y / N): n

Store username/password for OpenSearch Alerting email sender account? (y / N): n

(Re)generate internal passwords for NetBox? (Y / n): y

(Re)generate internal passwords for Keycloak's PostgreSQL database? (Y / n): y

(Re)generate internal superuser passwords for PostgreSQL? (Y / n): y

(Re)generate internal passwords for Valkey? (Y / n): y

Store password hash secret for Arkime viewer cluster? (y / N): n

Transfer self-signed client certificates to a remote log forwarder? (y / N): n
```

Start Malcolm:

```
$ ./scripts/start -f /path/to/kubeconfig.yaml
…
logstash | [2026-01-16T17:58:33,274][INFO ][logstash.agent           ] Pipelines running {:count=>7, :running_pipelines=>[:"malcolm-output", :"malcolm-input", :"malcolm-filescan", :"malcolm-suricata", :"malcolm-enrichment", :"malcolm-beats", :"malcolm-zeek"], :non_running_pipelines=>[]}

Started Malcolm

Malcolm services can be accessed at https://192.168.121.239/
------------------------------------------------------------------------------
```

Check the status of the Malcolm deployment with `./scripts/status`:

```
$ ./scripts/status -f /path/to/kubeconfig.yaml

Node Name | Hostname  | IP              | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods | 
----------+-----------+-----------------+-------------+---------------+-----------+-----------+-------------+--------------+--------------+---------------+--------------|
debian-13 | debian-13 | 192.168.121.239 | debian-13   | rke2          | 8000m     | 942.81m   | 11.79%      | 31.35Gi      | 2.31Gi       | 58.8Gi        | 44           | 

Pod Name                                      | State   | Pod IP       | Pod Kind   | Worker Node      | CPU Usage | Memory Usage | Container Name:Restarts       | Container Image                                    |
----------------------------------------------+---------+--------------+------------+------------------+-----------+--------------+-------------------------------+----------------------------------------------------|
api-deployment-7fff7bf884-84prz               | Running | 10.42.2.226  | ReplicaSet | debian-13   | 0.12m     | 68.89Mi      | api-container:0               | ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}                   |
arkime-deployment-68946dffcb-fx8nl            | Running | 10.42.13.42  | ReplicaSet | debian-13   | 309.86m   | 1.01Gi       | arkime-container:0            | ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}                |
dashboards-deployment-6456f67fb4-jhnqf        | Running | 10.42.11.184 | ReplicaSet | debian-13   | 85.4m     | 215.95Mi     | dashboards-container:0        | ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}            |
dashboards-helper-deployment-7d5d8c5ddf-tphbx | Running | 10.42.17.23  | ReplicaSet | debian-13   | 8.56m     | 47.26Mi      | dashboards-helper-container:0 | ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}     |
filebeat-deployment-855578fd56-wxz5t          | Running | 10.42.16.223 | ReplicaSet | debian-13   | 5.77m     | 278.45Mi     | filebeat-container:0          | ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}          |
filescan-deployment-7b675999dd-m7sx8          | Running | 10.42.2.227  | ReplicaSet | debian-13   | 4.32m     | 204.33Mi     | filescan-container:0          | ghcr.io/idaholab/malcolm/filescan:{{ site.malcolm.version }}              |
freq-deployment-5dbf7fd958-xdm4j              | Running | 10.42.9.23   | ReplicaSet | debian-13   | 1.13m     | 36.59Mi      | freq-container:0              | ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}                  |
htadmin-deployment-6779876475-h5wwh           | Running | 10.42.10.48  | ReplicaSet | debian-13   | 0.26m     | 43.36Mi      | htadmin-container:0           | ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}               |
keycloak-deployment-7fd4bdff5c-fkzxs          | Running | 10.42.9.24   | ReplicaSet | debian-13   | 0.03m     | 11.07Mi      | keycloak-container:0          | ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}              |
logstash-deployment-5bbcc5b775-bjk59          | Running | 10.42.11.185 | ReplicaSet | debian-13   | 68.84m    | 3.97Gi       | logstash-container:0          | ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}          |
netbox-deployment-987476c89-6vznb             | Running | 10.42.16.224 | ReplicaSet | debian-13   | 428.2m    | 1.09Gi       | netbox-container:0            | ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}                |
nginx-proxy-deployment-6d9b9858fd-q9w5z       | Running | 10.42.3.140  | ReplicaSet | debian-13   | 13.07m    | 25.78Mi      | nginx-proxy-container:0       | ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}           |
opensearch-deployment-6c546f45b9-n4czl        | Running | 10.42.7.165  | ReplicaSet | debian-13   | 887.36m   | 17.8Gi       | opensearch-container:0        | ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}            |
pcap-monitor-deployment-66dbd9c68f-22tkm      | Running | 10.42.10.46  | ReplicaSet | debian-13   | 183.31m   | 867.33Mi     | pcap-monitor-container:0      | ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}          |
postgres-deployment-5c78f478fb-nl4zn          | Running | 10.42.15.210 | ReplicaSet | debian-13   | 472.87m   | 85.33Mi      | postgres-container:0          | ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}            |
valkey-cache-deployment-5c776698fc-dvbp2      | Running | 10.42.5.20   | ReplicaSet | debian-13   | 9.58m     | 10.18Mi      | valkey-cache-container:0      | ghcr.io/idaholab/malcolm/valkey:{{ site.malcolm.version }}                |
valkey-deployment-75486865c5-4xscs            | Running | 10.42.15.209 | ReplicaSet | debian-13   | 9.66m     | 10.04Mi      | valkey-container:0            | ghcr.io/idaholab/malcolm/valkey:{{ site.malcolm.version }}                |
strelka-backend-deployment-6dcf7ccdcc-xjbxx   | Running | 10.42.5.21   | ReplicaSet | debian-13   | 4.72m     | 1.18Gi       | strelka-backend-container:0   | ghcr.io/idaholab/malcolm/strelka-backend:{{ site.malcolm.version }}       |
strelka-frontend-deployment-6988c75f8c-gmf8c  | Running | 10.42.6.23   | ReplicaSet | debian-13   | 0.03m     | 8.02Mi       | strelka-frontend-container:0  | ghcr.io/idaholab/malcolm/strelka-frontend:{{ site.malcolm.version }}      |
strelka-manager-deployment-f578ccc7-2vw7l     | Running | 10.42.12.15  | ReplicaSet | debian-13   | 2.41m     | 7.57Mi       | strelka-manager-container:0   | ghcr.io/idaholab/malcolm/strelka-manager:{{ site.malcolm.version }}       |
suricata-offline-deployment-86d4796bf7-wpzq5  | Running | 10.42.16.222 | ReplicaSet | debian-13   | 2882.76m  | 4.11Gi       | suricata-offline-container:0  | ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}              |
upload-deployment-7d8886d86b-qnncd            | Running | 10.42.4.174  | ReplicaSet | debian-13   | 78.27m    | 226.11Mi     | upload-container:0            | ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}           |
zeek-offline-deployment-fb7847b9b-jvtcj       | Running | 10.42.10.47  | ReplicaSet | debian-13   | 3016.28m  | 3.14Gi       | zeek-offline-container:0      | ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}                  |
```

View container logs for the Malcolm deployment with `./scripts/logs` (if **[stern](https://github.com/stern/stern)** present in `$PATH`):

```
$ ./scripts/logs -f /path/to/kubeconfig.yaml
api | [2023-04-24 20:55:59 +0000] [7] [INFO] Booting worker with pid: 7
dashboards |   log   [20:59:28.784] [info][server][OpenSearchDashboards][http] http server running at http://0.0.0.0:5601/dashboards
freq | 2023-04-24 20:57:09,481 INFO success: freq entered RUNNING state, process has stayed up for > than 5 seconds (startsecs)
htadmin | 2023-04-24 20:58:04,724 INFO success: nginx entered RUNNING state, process has stayed up for > than 15 seconds (startsecs)
opensearch | [2023-04-24T21:00:18,442][WARN ][o.o.c.m.MetadataIndexTemplateService] [opensearch-deployment-75498799f6-5v92w] index template [malcolm_template] has index patterns [arkime_sessions3-*] matching patterns from existing older templates [arkime_sessions3_ecs_template,arkime_sessions3_template] with patterns (arkime_sessions3_ecs_template => [arkime_sessions3-*],arkime_sessions3_template => [arkime_sessions3-*]); this template [malcolm_template] will take precedence during new index creation
pcap-capture | 8:57PM INF Listening at http://0.0.0.0:80 /...
pcap-monitor | 2023-04-24 20:59:53 INFO: ۞  started [1]
upload | 2023-04-24 20:59:27,496 INFO success: nginx entered RUNNING state, process has stayed up for > than 15 seconds (startsecs)
zeek-live | 8:59PM INF Listening at http://0.0.0.0:80 /...
zeek-offline | 2023-04-24 20:58:16,072 INFO success: pcap-zeek entered RUNNING state, process has stayed up for > than 15 seconds (startsecs)
suricata-live | 8:57PM INF Listening at http://0.0.0.0:80 /...
logstash | [2023-04-24T21:00:34,470][INFO ][logstash.agent           ] Pipelines running {:count=>6, :running_pipelines=>[:"malcolm-input", :"malcolm-output", :"malcolm-suricata", :"malcolm-beats", :"malcolm-enrichment", :"malcolm-zeek"], :non_running_pipelines=>[]}
…
```

The Malcolm [user interface](quickstart.md#UserInterfaceURLs) should be accessible at the IP address or hostname of the Kubernetes ingress controller.

# <a name="Future"></a> Future Enhancements

Deploying Malcolm with Kubernetes is a new (and still somewhat experimental) feature, and does not yet support the full range of Malcolm features. Development around these features is [ongoing](https://github.com/cisagov/Malcolm/issues?q=is%3Aissue+is%3Aopen+kubernetes). Some of the notable features that are still a work in progress for Kubernetes deployment include:

## <a name="FutureLiveCap"></a> Live Traffic Analysis

For now, network traffic artifacts for analysis are provided to a Malcolm deployment on Kubernetes via forwarding from a remote instance of [Hedgehog Linux](hedgehog.md) or via PCAP [upload](upload.md#Upload). [Future work](https://github.com/idaholab/Malcolm/issues/175) is needed to design and implement monitoring of network traffic in the cloud.

## <a name="FutureScaleOut"></a> Horizontal Scaling

For now, the Malcolm services running in Kubernetes are configured with `replicas: 1`. There is [more investigation and development](https://github.com/idaholab/Malcolm/issues/182) needed to ensure Malcolm's containers work correctly when horizontally scaled.

## <a name="FutureHelmChart"></a> Helm Chart

For now, Malcolm's Kubernetes deployment is managed via standard [Kubernetes manifests]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/). The Malcolm developers need to [look into](https://github.com/idaholab/Malcolm/issues/187) what a Malcolm Helm chart would look like and how it would fit in with the [deployment scripts](https://github.com/idaholab/Malcolm/issues/172) for [configuring](#Config) and [running](#Running) Malcolm, if at all.
