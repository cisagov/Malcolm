# <a name="Kubernetes"></a>Deploying Malcolm with Kubernetes

* [Deploying Malcolm with Kubernetes](#Kubernetes)
    - [System](#System)
        + [Ingress Controllers](#Ingress)
            * [Ingress-NGINX Controller](#IngressNGINX)
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

## <a name="System"></a> System

### <a name="Ingress"></a> Ingress Controllers

There exist a variety of ingress controllers for Kubernetes suitable for different Kubernetes providers and environments. A few sample manifests for ingress controllers can be found in Malcolm's [`kubernetes`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/) directory, prefixed with `99-ingress-…`:

* [`kubernetes/99-ingress-nginx.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-nginx.yml.example) - an example ingress manifest for Malcolm using the [Ingress-NGINX controller for Kubernetes](https://github.com/kubernetes/ingress-nginx). The Ingress-NGINX controller has been used internally on self-hosted Kubernetes clusters during Malcolm's development and testing.
* [`kubernetes/99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example) - an example ingress manifest for Malcolm using the [AWS Load Balancer (ALB) Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/#aws-load-balancer-controller). Users likely will prefer to use ALB to [deploy Malcolm on Amazon Elastic Kubernetes Service (EKS)](aws.md#AWSEKSAuto).

Before [running](#Running) Malcolm, either copy one of the `99-ingress-…` files to `99-ingress.yml` as a starting point to define the ingress or define a custom manifest file and save it as `99-ingress.yml`.

#### <a name="IngressNGINX"></a> Ingress-NGINX Controller

Malcolm's [ingress controller manifest]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-nginx.yml) uses the [Ingress-NGINX controller for Kubernetes](https://github.com/kubernetes/ingress-nginx). A few Malcolm features require some customization when installing and configuring the Ingress-NGINX controller. As well as being listed below, see [kubernetes/vagrant/deploy_ingress_nginx.sh]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/deploy_ingress_nginx.sh) for an example of how to configure and apply the Ingress-NGINX controller for Kubernetes.

* To forward logs from a remote instance of [Hedgehog Linux](hedgehog.md):
    - See ["Exposing TCP and UDP services"](https://kubernetes.github.io/ingress-nginx/user-guide/exposing-tcp-udp-services/) in the Ingress-NGINX documentation.
    - Configure the controller to start up with the `--tcp-services-configmap=ingress-nginx/tcp-services` flag:
        ```
        apiVersion: apps/v1
        kind: Deployment
        metadata:
        …
          name: ingress-nginx-controller
          namespace: ingress-nginx
        spec:
        …
          template:
        …
            spec:
              containers:
                + args:
                    + /nginx-ingress-controller
                    + --publish-service=$(POD_NAMESPACE)/ingress-nginx-controller
                    + --election-id=ingress-nginx-leader
                    + --controller-class=k8s.io/ingress-nginx
                    + --ingress-class=nginx
                    + --configmap=$(POD_NAMESPACE)/ingress-nginx-controller
                    + --validating-webhook=:8443
                    + --validating-webhook-certificate=/usr/local/certificates/cert
                    + --validating-webhook-key=/usr/local/certificates/key
                    + --enable-ssl-passthrough
                    + --tcp-services-configmap=ingress-nginx/tcp-services
        …
        ```
    - Add the appropriate ports (minimally TCP ports 5044 and 9200) to the `ingress-nginx-controller` load-balancer service definition:
        ```
          apiVersion: v1
          kind: Service
          metadata:
          …
            name: ingress-nginx-controller
            namespace: ingress-nginx
          spec:
            externalTrafficPolicy: Local
            ipFamilies:
              - IPv4
            ipFamilyPolicy: SingleStack
            ports:
              - appProtocol: http
                name: http
                port: 80
                protocol: TCP
                targetPort: http
              - appProtocol: https
                name: https
                port: 443
                protocol: TCP
                targetPort: https
              - appProtocol: tcp
                name: lumberjack
                port: 5044
                targetPort: 5044
                protocol: TCP
              - appProtocol: tcp
                name: tcpjson
                port: 5045
                targetPort: 5045
                protocol: TCP
          - appProtocol: tcp
                name: opensearch
                port: 9200
                targetPort: 9200
                protocol: TCP
          …
            type: LoadBalancer
        ```
    - Add the appropriate ports (minimally TCP ports 5044 and 9200) to the `ingress-nginx-controller` deployment container's definition:
        ```
        apiVersion: apps/v1
        kind: Deployment
        metadata:
        …
          name: ingress-nginx-controller
          namespace: ingress-nginx
        spec:
        …
          template:
        …
            spec:
              containers:
        …
                  ports:
                    * containerPort: 80
                      name: http
                      protocol: TCP
                    * containerPort: 443
                      name: https
                      protocol: TCP
                    * containerPort: 8443
                      name: webhook
                      protocol: TCP
                    * name: lumberjack
                      containerPort: 5044
                      protocol: TCP
                    * name: tcpjson
                      containerPort: 5045
                      protocol: TCP
                    * name: opensearch
                      containerPort: 9200
                      protocol: TCP
        …
        ```

* To use [SSL Passthrough](https://kubernetes.github.io/ingress-nginx/user-guide/tls/) to have the Kubernetes gateway use Malcolm's TLS certificates rather than its own:
    - Configure the controller to start up with the `--enable-ssl-passthrough` flag:
        ```
        apiVersion: apps/v1
        kind: Deployment
        metadata:
        …
          name: ingress-nginx-controller
          namespace: ingress-nginx
        spec:
        …
          template:
        …
            spec:
              containers:
                * args:
                    * /nginx-ingress-controller
                    * --publish-service=$(POD_NAMESPACE)/ingress-nginx-controller
                    * --election-id=ingress-nginx-leader
                    * --controller-class=k8s.io/ingress-nginx
                    * --ingress-class=nginx
                    * --configmap=$(POD_NAMESPACE)/ingress-nginx-controller
                    * --validating-webhook=:8443
                    * --validating-webhook-certificate=/usr/local/certificates/cert
                    * --validating-webhook-key=/usr/local/certificates/key
                    * --enable-ssl-passthrough
                    * --tcp-services-configmap=ingress-nginx/tcp-services
        …
        ```

    - Modify Malcolm's [ingress controller manifest]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-nginx.yml.example) to specify the `host:` value and use [host-based routing](https://kubernetes.github.io/ingress-nginx/user-guide/basic-usage/):

        ```
        …
        spec:
          rules:
          + host: malcolm.example.org
            http:
              paths:
              + path: /
                pathType: Prefix
                backend:
                  service:
                    name: nginx-proxy
                    port:
                      number: 443
        …
        ```

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

While Malcolm can manage its own single-node OpenSearch instance as part of its Kubernetes deployment, users may want to use an existing multi-node OpenSearch or Elasticsearch cluster hosted on Kubernetes or some other provider (see, for example, ["Setup OpenSearch multi-node cluster on Kubernetes using Helm Charts"](https://opensearch.org/blog/setup-multinode-cluster-kubernetes/) on the OpenSearch blog and ["OpenSearch Kubernetes Operator"](https://opensearch.org/docs/latest/tools/k8s-operator/) in the OpenSearch documentation). Review Malcolm's documentation on [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance) to configure a Malcolm deployment to use an OpenSearch or Elasticesarch cluster.

### <a name="PVC"></a> PersistentVolumeClaim Definitions

Malcolm requires persistent [storage](https://kubernetes.io/docs/concepts/storage/) to be configured for its configuration and data files. There are various implementations for provisioning PersistentVolume resources using [storage classes](https://kubernetes.io/docs/concepts/storage/storage-classes/). Regardless of the types of storage underlying the PersistentVolumes, Malcolm requires the following PersistentVolumeClaims to be defined in the `malcolm` namespace:

* `config-claim` - storage for configuration files
* `opensearch-backup-claim` - storage for OpenSearch snapshots (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `opensearch-claim` - storage for OpenSearch indices (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `pcap-claim` - storage for PCAP artifacts
* `runtime-logs-claim` - storage for runtime logs for some containers (e.g., nginx, Arkime)
* `suricata-claim` - storage for Suricata logs
* `zeek-claim` - storage for Zeek logs and files extracted by Zeek

An example of how these PersistentVolume and PersistentVolumeClaim objects could be defined using NFS can be found in the [kubernetes/01-volumes-nfs.yml.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-nfs.yml.example) or [kubernetes/01-volumes-vagrant-nfs-server.yml.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-vagrant-nfs-server.yml.example) manifest files. The latter of the two manifest examples is used in conjunction with the NFS server Vagrantfile example: [kubernetes/vagrant/Vagrantfile_NFS_Server.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile_NFS_Server.example) . Before [running](#Running) Malcolm, copy either `01-volumes-vagrant-nfs-server.yml.example` to `01-volumes.yml` (for the Vagrant provided NFS server) or copy `01-volumes-nfs.yml.example` to `01-volumes.yml` and modify (or replace) its contents to define the PersistentVolumeClaim objects configured for your own NFS server IP address and exported paths.

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
Node Name | Hostname | IP            | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods |
server    | server   | 192.168.56.10 | server      | k3s           | 4000m     | 30.37m    | 0.76%       | 7.77Gi       | 1.2Gi        | 61.28Gi       | 7            |
agent2    | agent2   | 192.168.56.12 | agent2      | k3s           | 6000m     | 156.42m   | 2.61%       | 19.55Gi      | 14.47Gi      | 61.28Gi       | 13           |
agent1    | agent1   | 192.168.56.11 | agent1      | k3s           | 6000m     | 861.34m   | 14.36%      | 19.55Gi      | 9.29Gi       | 61.28Gi       | 11           |

Pod Name                                       | State   | Pod IP     | Pod Kind   | Worker Node | CPU Usage | Memory Usage | Container Name:Restarts        | Container Image              |
api-deployment-6f4686cf59-bn286                | Running | 10.42.2.14 | ReplicaSet | agent1      | 0.11m     | 59.62Mi      | api-container:0                | api:{{ site.malcolm.version }}               |
file-monitor-deployment-855646bd75-vk7st       | Running | 10.42.2.16 | ReplicaSet | agent1      | 8.47m     | 1.46Gi       | file-monitor-container:0       | file-monitor:{{ site.malcolm.version }}      |
zeek-live-deployment-64b69d4b6f-947vr          | Running | 10.42.2.17 | ReplicaSet | agent1      | 0.02m     | 12.44Mi      | zeek-live-container:0          | zeek:{{ site.malcolm.version }}              |
dashboards-helper-deployment-69dc54f6b6-ln4sq  | Running | 10.42.2.15 | ReplicaSet | agent1      | 10.77m    | 38.43Mi      | dashboards-helper-container:0  | dashboards-helper:{{ site.malcolm.version }} |
upload-deployment-586568844b-4jnk9             | Running | 10.42.2.18 | ReplicaSet | agent1      | 0.15m     | 29.78Mi      | upload-container:0             | file-upload:{{ site.malcolm.version }}       |
filebeat-deployment-6ff8bc444f-t7h49           | Running | 10.42.2.20 | ReplicaSet | agent1      | 2.84m     | 70.71Mi      | filebeat-container:0           | filebeat-oss:{{ site.malcolm.version }}      |
zeek-offline-deployment-844f4865bd-g2sdm       | Running | 10.42.2.21 | ReplicaSet | agent1      | 0.17m     | 41.92Mi      | zeek-offline-container:0       | zeek:{{ site.malcolm.version }}              |
logstash-deployment-6fbc9fdcd5-hwx8s           | Running | 10.42.2.22 | ReplicaSet | agent1      | 85.55m    | 2.91Gi       | logstash-container:0           | logstash-oss:{{ site.malcolm.version }}      |
netbox-deployment-cdcff4977-hbbw5              | Running | 10.42.2.23 | ReplicaSet | agent1      | 807.64m   | 702.86Mi     | netbox-container:0             | netbox:{{ site.malcolm.version }}            |
suricata-offline-deployment-6ccdb89478-z5696   | Running | 10.42.2.19 | ReplicaSet | agent1      | 0.22m     | 34.88Mi      | suricata-offline-container:0   | suricata:{{ site.malcolm.version }}          |
dashboards-deployment-69b5465db-vz88g          | Running | 10.42.1.14 | ReplicaSet | agent2      | 0.94m     | 100.12Mi     | dashboards-container:0         | dashboards:{{ site.malcolm.version }}        |
redis-cache-deployment-5f77d47b8b-z7t2z        | Running | 10.42.1.15 | ReplicaSet | agent2      | 3.57m     | 7.36Mi       | redis-cache-container:0        | redis:{{ site.malcolm.version }}             |
suricata-live-deployment-6494c77759-9rlnt      | Running | 10.42.1.16 | ReplicaSet | agent2      | 0.02m     | 9.69Mi       | suricata-live-container:0      | suricata:{{ site.malcolm.version }}          |
freq-deployment-cfd84fd97-dnngf                | Running | 10.42.1.17 | ReplicaSet | agent2      | 0.2m      | 26.36Mi      | freq-container:0               | freq:{{ site.malcolm.version }}              |
arkime-deployment-56999cdd66-s98pp             | Running | 10.42.1.18 | ReplicaSet | agent2      | 4.15m     | 113.07Mi     | arkime-container:0             | arkime:{{ site.malcolm.version }}            |
pcap-monitor-deployment-594ff674c4-fsm7m       | Running | 10.42.1.19 | ReplicaSet | agent2      | 1.24m     | 48.44Mi      | pcap-monitor-container:0       | pcap-monitor:{{ site.malcolm.version }}      |
pcap-capture-deployment-7c8bf6957-jzpzn        | Running | 10.42.1.20 | ReplicaSet | agent2      | 0.02m     | 9.64Mi       | pcap-capture-container:0       | pcap-capture:{{ site.malcolm.version }}      |
postgres-deployment-5879b8dffc-kkt56           | Running | 10.42.1.21 | ReplicaSet | agent2      | 70.91m    | 33.02Mi      | postgres-container:0           | postgresql:{{ site.malcolm.version }}        |
htadmin-deployment-6fc46888b9-sq6ln            | Running | 10.42.1.23 | ReplicaSet | agent2      | 0.14m     | 30.53Mi      | htadmin-container:0            | htadmin:{{ site.malcolm.version }}           |
redis-deployment-5bcd8f6c96-j5xpf              | Running | 10.42.1.24 | ReplicaSet | agent2      | 1.46m     | 7.34Mi       | redis-container:0              | redis:{{ site.malcolm.version }}             |
nginx-proxy-deployment-69fcc4968d-f68tq        | Running | 10.42.1.22 | ReplicaSet | agent2      | 0.31m     | 22.63Mi      | nginx-proxy-container:0        | nginx-proxy:{{ site.malcolm.version }}       |
opensearch-deployment-75498799f6-4zmwd         | Running | 10.42.1.25 | ReplicaSet | agent2      | 89.8m     | 11.03Gi      | opensearch-container:0         | opensearch:{{ site.malcolm.version }}        |
```

The other control scripts (`stop`, `restart`, `logs`, etc.) work in a similar manner as in a Docker-based deployment. One notable difference is the `wipe` script: data on PersistentVolume storage cannot be deleted by `wipe`. It must be deleted manually on the storage media underlying the PersistentVolumes.

Malcolm's control scripts require the [official Python 3 client library for Kubernetes](https://github.com/kubernetes-client/python) to configure and run Malcolm with Kubernetes. It is also recommended to install **[stern](https://github.com/stern/stern)**, which is used by the `./scripts/logs` script to tail Malcolm's container logs.

# <a name="Example"></a> Deployment Example

Here is a basic step-by-step example illustrating how to deploy Malcolm with Kubernetes. For the sake of simplicity, this example uses Vagrant: see [kubernetes/vagrant/Vagrantfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile) to create a virtualized Kubernetes cluster with one control plane node and two worker nodes or see [kubernetes/vagrant/Vagrantfile_NFS_Server.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile_NFS_Server.example) to include an NFS server with the cluster described above. It assumes users have downloaded and extracted the [release tarball]({{ site.github.repository_url }}/releases/latest) or used `./scripts/malcolm_appliance_packager.sh` to package up the files needed to run Malcolm.

```
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

```
$ ./scripts/status -f /path/to/kubeconfig.yaml
Node Name | Hostname | IP            | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods |
agent2    | agent2   | 192.168.56.12 | agent2      | k3s           | 6000m     | 32.06m    | 0.53%       | 19.55Gi      | 346.3Mi      | 61.28Gi       | 1            |
agent1    | agent1   | 192.168.56.11 | agent1      | k3s           | 6000m     | 26.7m     | 0.45%       | 19.55Gi      | 353.2Mi      | 61.28Gi       | 1            |
server    | server   | 192.168.56.10 | server      | k3s           | 4000m     | 290.15m   | 7.25%       | 7.77Gi       | 1.04Gi       | 61.28Gi       | 7            |

Pod Name | State | Pod IP | Pod Kind | Worker Node | CPU Usage | Memory Usage | Container Name:Restarts | Container Image |
```

Run `./scripts/configure` to configure Malcolm. For an in-depth treatment of the configuration options, see the **Malcolm Configuration Menu Items** section in **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems)**.:


```
--- Malcolm Configuration Menu ---
Select an item number to configure, or an action:
├── 1. Container Runtime (current: kubernetes)
│   ├── 2. Process Group ID (current: 1000)
│   └── 3. Process User ID (current: 1000)
├── 4. Run Profile (current: malcolm)
│   ├── 5. Dark Mode for Dashboards (current: Yes)
│   ├── 6. Forward Logs to Remote Secondary Store (current: No)
│   ├── 7. Logstash Memory (current: 6g)
│   ├── 8. Logstash Workers (current: 6)
│   ├── 9. OpenSearch Memory (current: 31g)
│   └── 10. Primary Document Store (current: opensearch-local)
├── 11. Require HTTPS Connections (current: Yes)
├── 12. IPv4 for nginx Resolver Directive (current: Yes)
├── 13. IPv6 for nginx Resolver Directive (current: No)
├── 14. Use Default Storage Location (current: Yes)
├── 15. Clean Up Artifacts (current: Yes)
│   ├── 16. Delete Old Indices (current: Yes)
│   │   ├── 17. Index Prune Threshold (current: 500G)
│   │   └── 18. Prune Indices by Name (current: No)
│   └── 19. Delete Old PCAP (current: Yes)
│       └── 20. Delete PCAP Threshold (current: 5%)
├── 21. Enable Arkime Index Management (current: No)
├── 22. Enable Arkime Analysis (current: Yes)
├── 23. Enable Suricata Analysis (current: Yes)
│   └── 24. Enable Suricata Rule Updates (current: Yes)
├── 25. Enable Zeek Analysis (current: Yes)
│   ├── 26. Enable Zeek File Extraction (current: Yes)
│   │   └── 27. File Extraction Mode (current: interesting)
│   │       ├── 28. Extracted File Percent Threshold (current: 100)
│   │       ├── 29. Extracted File Size Threshold (current: 25G)
│   │       ├── 30. File Preservation (current: quarantined)
│   │       ├── 31. Preserved Files HTTP Server (current: Yes)
│   │       │   ├── 32. Downloaded Preserved File Password (current: ********)
│   │       │   └── 33. Zip Downloads (current: Yes)
│   │       ├── 34. Scan with capa (current: Yes)
│   │       ├── 35. Scan with ClamAV (current: Yes)
│   │       ├── 36. Scan with YARA (current: Yes)
│   │       ├── 37. Update Scan Rules (current: Yes)
│   │       └── 38. VirusTotal API Key (current: empty)
│   ├── 39. Enable Zeek ICS/OT Analyzers (current: Yes)
│   │   └── 40. Enable Zeek ICS "Best Guess" (current: Yes)
│   └── 41. Use Threat Feeds for Zeek Intelligence (current: Yes)
│       ├── 42. Cron Expression for Threat Feed Updates (current: 0 0 * * *)
│       ├── 43. Intel::item_expiration Timeout (current: -1min)
│       ├── 44. Pull Threat Intelligence Feeds on Startup (current: Yes)
│       └── 45. Threat Indicator "Since" Period (current: 7 days ago)
├── 46. Enrich with Reverse DNS Lookups (current: No)
├── 47. Enrich with Manufacturer (OUI) Lookups (current: Yes)
├── 48. Enrich with Frequency Scoring (current: Yes)
├── 49. NetBox Mode (current: Local)
│   ├── 50. Auto-Create Subnet Prefixes (current: Yes)
│   ├── 51. Auto-Populate NetBox Inventory (current: Yes)
│   ├── 52. NetBox Enrichment (current: Yes)
│   └── 53. NetBox Site Name (current: Malcolm)
├── 54. Expose Malcolm Service Ports (current: Customize)
│   ├── 55. Expose Filebeat TCP (current: Yes)
│   │   └── 56. Use Filebeat TCP Listener Defaults (current: Yes)
│   ├── 57. Syslog TCP Port (current: 514)
│   └── 58. Syslog UDP Port (current: 514)
├── 59. Network Traffic Node Name (current: malcolm-cluster)
└── 60. Capture Live Network Traffic (current: No)

--- Actions ---
  s. Save and Continue
  w. Where Is...? (search for settings)
  d. Debug menu structure
  x. Exit Installer
---------------------------------

Enter item number or action: s

…

============================================================
FINAL CONFIGURATION SUMMARY
============================================================
Configuration Only                                : Yes
Configuration Directory                           : /home/user/Malcolm/config
Container Runtime                                 : kubernetes
Run Profile                                       : malcolm
Process UID/GID                                   : 1000/1000
HTTPS/SSL                                         : Yes
Node Name                                         : malcolm-cluster
============================================================

Proceed with Malcolm installation using the above configuration? (y / N): y

```

Run `./scripts/auth_setup` and answer the questions to [configure authentication](authsetup.md#AuthSetup):

```
$ ./scripts/auth_setup -f /path/to/kubeconfig.yaml

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
12: redis - (Re)generate internal passwords for Redis
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

(Re)generate internal passwords for Redis? (Y / n): y

Store password hash secret for Arkime viewer cluster? (y / N): n

Transfer self-signed client certificates to a remote log forwarder? (y / N): n
```

Next, copy `./kubernetes/01-volumes-vagrant-nfs-server.yml.example` to `./kubernetes/01-volumes.yml` (when using the Vagrant provided NFS server) or copy `./kubernetes/01-volumes-nfs.yml.example` to `./kubernetes/01-volumes.yml` and edit that file to define the [required PersistentVolumeClaims](#PVC) there.

```
$ cp -v ./kubernetes/01-volumes-nfs.yml.example ./kubernetes/01-volumes.yml
'./kubernetes/01-volumes-nfs.yml.example' -> './kubernetes/01-volumes.yml'

$ vi ./kubernetes/01-volumes.yml
…

$ grep -A 3 PersistentVolumeClaim ./kubernetes/01-volumes.yml
kind: PersistentVolumeClaim
metadata:
  name: pcap-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: zeek-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: suricata-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: config-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: runtime-logs-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: opensearch-claim
  namespace: malcolm
--
kind: PersistentVolumeClaim
metadata:
  name: opensearch-backup-claim
  namespace: malcolm

```

Start Malcolm:

```
$ ./scripts/start -f /path/to/kubeconfig.yaml
…
logstash | [2023-04-24T21:00:34,470][INFO ][logstash.agent           ] Pipelines running {:count=>6, :running_pipelines=>[:"malcolm-input", :"malcolm-output", :"malcolm-suricata", :"malcolm-beats", :"malcolm-enrichment", :"malcolm-zeek"], :non_running_pipelines=>[]}

Started Malcolm

Malcolm services can be accessed at https://192.168.56.10/
------------------------------------------------------------------------------
```

Check the status of the Malcolm deployment with `./scripts/status`:

```
$ ./scripts/status -f /path/to/kubeconfig.yaml

Node Name | Hostname | IP            | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods |
server    | server   | 192.168.56.10 | server      | k3s           | 4000m     | 47.03m    | 1.18%       | 7.77Gi       | 1.14Gi       | 61.28Gi       | 7            |
agent1    | agent1   | 192.168.56.11 | agent1      | k3s           | 6000m     | 3677.42m  | 61.29%      | 19.55Gi      | 4.95Gi       | 61.28Gi       | 12           |
agent2    | agent2   | 192.168.56.12 | agent2      | k3s           | 6000m     | 552.71m   | 9.21%       | 19.55Gi      | 13.27Gi      | 61.28Gi       | 12           |

Pod Name                                       | State   | Pod IP     | Pod Kind   | Worker Node | CPU Usage | Memory Usage | Container Name:Restarts        | Container Image              |
redis-cache-deployment-5f77d47b8b-jr9nt        | Running | 10.42.2.6  | ReplicaSet | agent2      | 1.89m     | 7.24Mi       | redis-cache-container:0        | redis:{{ site.malcolm.version }}             |
redis-deployment-5bcd8f6c96-bkzmh              | Running | 10.42.2.5  | ReplicaSet | agent2      | 1.62m     | 7.52Mi       | redis-container:0              | redis:{{ site.malcolm.version }}             |
dashboards-helper-deployment-69dc54f6b6-ks7ps  | Running | 10.42.2.4  | ReplicaSet | agent2      | 12.95m    | 40.75Mi      | dashboards-helper-container:0  | dashboards-helper:{{ site.malcolm.version }} |
freq-deployment-cfd84fd97-5bwp6                | Running | 10.42.2.8  | ReplicaSet | agent2      | 0.11m     | 26.33Mi      | freq-container:0               | freq:{{ site.malcolm.version }}              |
pcap-capture-deployment-7c8bf6957-hkvkn        | Running | 10.42.2.12 | ReplicaSet | agent2      | 0.02m     | 9.21Mi       | pcap-capture-container:0       | pcap-capture:{{ site.malcolm.version }}      |
nginx-proxy-deployment-69fcc4968d-m57rz        | Running | 10.42.2.10 | ReplicaSet | agent2      | 0.91m     | 22.72Mi      | nginx-proxy-container:0        | nginx-proxy:{{ site.malcolm.version }}       |
htadmin-deployment-6fc46888b9-vpt7l            | Running | 10.42.2.7  | ReplicaSet | agent2      | 0.16m     | 30.21Mi      | htadmin-container:0            | htadmin:{{ site.malcolm.version }}           |
opensearch-deployment-75498799f6-5v92w         | Running | 10.42.2.13 | ReplicaSet | agent2      | 139.2m    | 10.86Gi      | opensearch-container:0         | opensearch:{{ site.malcolm.version }}        |
zeek-live-deployment-64b69d4b6f-fcb6n          | Running | 10.42.2.9  | ReplicaSet | agent2      | 0.02m     | 109.55Mi     | zeek-live-container:0          | zeek:{{ site.malcolm.version }}              |
dashboards-deployment-69b5465db-kgsqk          | Running | 10.42.2.3  | ReplicaSet | agent2      | 14.98m    | 108.85Mi     | dashboards-container:0         | dashboards:{{ site.malcolm.version }}        |
arkime-deployment-56999cdd66-xxpw9             | Running | 10.42.2.11 | ReplicaSet | agent2      | 208.95m   | 78.42Mi      | arkime-container:0             | arkime:{{ site.malcolm.version }}            |
api-deployment-6f4686cf59-xt9md                | Running | 10.42.1.3  | ReplicaSet | agent1      | 0.14m     | 56.88Mi      | api-container:0                | api:{{ site.malcolm.version }}               |
postgres-deployment-5879b8dffc-lb4qm           | Running | 10.42.1.6  | ReplicaSet | agent1      | 141.2m    | 48.02Mi      | postgres-container:0           | postgresql:{{ site.malcolm.version }}        |
pcap-monitor-deployment-594ff674c4-fwq7g       | Running | 10.42.1.12 | ReplicaSet | agent1      | 3.93m     | 46.44Mi      | pcap-monitor-container:0       | pcap-monitor:{{ site.malcolm.version }}      |
suricata-offline-deployment-6ccdb89478-j5fgj   | Running | 10.42.1.10 | ReplicaSet | agent1      | 10.42m    | 35.12Mi      | suricata-offline-container:0   | suricata:{{ site.malcolm.version }}          |
suricata-live-deployment-6494c77759-rpt48      | Running | 10.42.1.8  | ReplicaSet | agent1      | 0.01m     | 9.62Mi       | suricata-live-container:0      | suricata:{{ site.malcolm.version }}          |
netbox-deployment-cdcff4977-7ns2q              | Running | 10.42.1.7  | ReplicaSet | agent1      | 830.47m   | 530.7Mi      | netbox-container:0             | netbox:{{ site.malcolm.version }}            |
zeek-offline-deployment-844f4865bd-7x68b       | Running | 10.42.1.9  | ReplicaSet | agent1      | 1.44m     | 43.66Mi      | zeek-offline-container:0       | zeek:{{ site.malcolm.version }}              |
filebeat-deployment-6ff8bc444f-pdgzj           | Running | 10.42.1.11 | ReplicaSet | agent1      | 0.78m     | 75.25Mi      | filebeat-container:0           | filebeat-oss:{{ site.malcolm.version }}      |
file-monitor-deployment-855646bd75-nbngq       | Running | 10.42.1.4  | ReplicaSet | agent1      | 1.69m     | 1.46Gi       | file-monitor-container:0       | file-monitor:{{ site.malcolm.version }}      |
upload-deployment-586568844b-9s7f5             | Running | 10.42.1.13 | ReplicaSet | agent1      | 0.14m     | 29.62Mi      | upload-container:0             | file-upload:{{ site.malcolm.version }}       |
logstash-deployment-6fbc9fdcd5-2hhx8           | Running | 10.42.1.5  | ReplicaSet | agent1      | 3236.29m  | 357.36Mi     | logstash-container:0           | logstash-oss:{{ site.malcolm.version }}      |
```

View container logs for the Malcolm deployment with `./scripts/logs` (if **[stern](https://github.com/stern/stern)** present in `$PATH`):

```
$ ./scripts/logs -f /path/to/kubeconfig.yaml
api | [2023-04-24 20:55:59 +0000] [7] [INFO] Booting worker with pid: 7
dashboards |   log   [20:59:28.784] [info][server][OpenSearchDashboards][http] http server running at http://0.0.0.0:5601/dashboards
file-monitor | 2023-04-24 20:59:38 INFO: ۞  started [1]
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
