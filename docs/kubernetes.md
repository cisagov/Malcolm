# <a name="Kubernetes"></a>Deploying Malcolm with Kubernetes

* [Deploying Malcolm with Kubernetes](#Kubernetes)
    - [System](#System)
        + [Ingress Controllers](#Ingress)
            * [Ingress-NGINX Controller](#IngressNGINX)
        + [Kubernetes Provider Settings](#Limits)
* [Configuration](#Config)
    - [OpenSearch Instances](#OpenSearchInstances)
    - [PersistentVolumeClaim Definitions](#PVC)
* [Running Malcolm](#Running)
* [Deployment Example](#Example)n
* [Future Enhancements](#Future)
    - [Live Traffic Analysis](#FutureLiveCap)
    - [Horizontal Scaling](#FutureScaleOut)
    - [Helm Chart](#FutureHelmChart)
* [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](kubernetes-eks.md#KubernetesEKS)

This document assumes good working knowledge of Kubernetes (K8s). The comprehensive [Kubernetes documentation](https://kubernetes.io/docs/home/) is a good place to go for more information about Kubernetes.

## <a name="System"></a> System

### <a name="Ingress"></a> Ingress Controllers

There exist a variety of ingress controllers for Kubernetes suitable for different Kubernetes providers and environments. A few sample manifests for ingress controllers can be found in Malcolm's [`kubernetes`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/) directory, prefixed with `99-ingress-…`:

* [`kubernetes/99-ingress-nginx.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-nginx.yml.example) - an example ingress manifest for Malcolm using the [Ingress-NGINX controller for Kubernetes](https://github.com/kubernetes/ingress-nginx). The Ingress-NGINX controller has been used internally on self-hosted Kubernetes clusters during Malcolm's development and testing.
* [`kubernetes/99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example) - an example ingress manifest for Malcolm using the [AWS Load Balancer (ALB) Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.5/#aws-load-balancer-controller). Users likely will prefer to use ALB to [deploy Malcolm on Amazon Elastic Kubernetes Service (EKS)](kubernetes-eks.md#KubernetesEKS).

Before [running](#Running) Malcolm, either copy one of the `99-ingress-…` files to `99-ingress.yml` as a starting point to define the ingress or define a custom manifest file and save it as `99-ingress.yml`.

#### <a name="IngressNGINX"></a> Ingress-NGINX Controller

Malcolm's [ingress controller manifest]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-nginx.yml) uses the [Ingress-NGINX controller for Kubernetes](https://github.com/kubernetes/ingress-nginx). A few Malcolm features require some customization when installing and configuring the Ingress-NGINX controller. As well as being listed below, see [kubernetes/vagrant/deploy_ingress_nginx.sh]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/deploy_ingress_nginx.sh) for an example of how to configure and apply the Ingress-NGINX controller for Kubernetes.

* To [forward](malcolm-hedgehog-e2e-iso-install.md#HedgehogConfigForwarding) logs from a remote instance of [Hedgehog Linux](hedgehog.md):
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
        ---
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

* System settings (e.g., in `/etc/sysctl.conf`)
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

Malcolm's configuration and runtime scripts (e.g., `./scripts/configure`, `./scripts/auth_setup`, `./scripts/start`, etc.) are used for both Docker- and Kubernetes-based deployments. In order to indicate to these scripts that Kubernetes is being used rather than `docker-compose`, users can provide the script with the [kubeconfig file](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) used to communicate with the API server of the Kubernetes cluster (e.g., `./scripts/configure -f k3s.yaml` or `./scripts/start -f kubeconfig.yaml`, etc.). The scripts will detect whether the YAML file specified is a kubeconfig file or a Docker compose file and act accordingly.

Run `./scripts/configure` and answer the questions to configure Malcolm. For an in-depth treatment of these configuration questions, see the **Configuration** section in **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)**. Users will need to run [`./scripts/auth_setup`](authsetup.md#AuthSetup) to configure authentication.

### <a name="OpenSearchInstances"></a> OpenSearch Instances

While Malcolm can manage its own single-node OpenSearch instance as part of its Kubernetes deployment, users may want to use an existing multi-node OpenSearch cluster hosted on Kubernetes or some other provider (see, for example, ["Setup OpenSearch multi-node cluster on Kubernetes using Helm Charts"](https://opensearch.org/blog/setup-multinode-cluster-kubernetes/) on the OpenSearch blog and ["OpenSearch Kubernetes Operator"](https://opensearch.org/docs/latest/tools/k8s-operator/) in the OpenSearch documentation). Review Malcolm's documentation on [OpenSearch instances](opensearch-instances.md#OpenSearchInstance) to configure a Malcolm deployment to use an OpenSearch cluster.

### <a name="PVC"></a> PersistentVolumeClaim Definitions

Malcolm requires persistent [storage](https://kubernetes.io/docs/concepts/storage/) to be configured for its configuration and data files. There are various implementations for provisioning PersistentVolume resources using [storage classes](https://kubernetes.io/docs/concepts/storage/storage-classes/). Regardless of the types of storage underlying the PersistentVolumes, Malcolm requires the following PersistentVolumeClaims to be defined in the `malcolm` namespace:

* `config-claim` - storage for configuration files
* `opensearch-backup-claim` - storage for OpenSearch snapshots (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `opensearch-claim` - storage for OpenSearch indices (if using a local [OpenSearch instance](opensearch-instances.md#OpenSearchInstance))
* `pcap-claim` - storage for PCAP artifacts
* `runtime-logs-claim` - storage for runtime logs for some containers (e.g., nginx, Arkime)
* `suricata-claim` - storage for Suricata logs
* `zeek-claim` - storage for Zeek logs and files extracted by Zeek

An example of how these PersistentVolume and PersistentVolumeClaim objects could be defined using NFS can be found in the [kubernetes/01-volumes-nfs.yml.example]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-nfs.yml.example) manifest file. Before [running](#Running) Malcolm, copy the `01-volumes-nfs.yml.example` file to `01-volumes.yml` and modify (or replace) its contents to define the PersistentVolumeClaim objects.

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
api-deployment-6f4686cf59-bn286                | Running | 10.42.2.14 | ReplicaSet | agent1      | 0.11m     | 59.62Mi      | api-container:0                | api:23.07.1               |
file-monitor-deployment-855646bd75-vk7st       | Running | 10.42.2.16 | ReplicaSet | agent1      | 8.47m     | 1.46Gi       | file-monitor-container:0       | file-monitor:23.07.1      |
zeek-live-deployment-64b69d4b6f-947vr          | Running | 10.42.2.17 | ReplicaSet | agent1      | 0.02m     | 12.44Mi      | zeek-live-container:0          | zeek:23.07.1              |
dashboards-helper-deployment-69dc54f6b6-ln4sq  | Running | 10.42.2.15 | ReplicaSet | agent1      | 10.77m    | 38.43Mi      | dashboards-helper-container:0  | dashboards-helper:23.07.1 |
upload-deployment-586568844b-4jnk9             | Running | 10.42.2.18 | ReplicaSet | agent1      | 0.15m     | 29.78Mi      | upload-container:0             | file-upload:23.07.1       |
filebeat-deployment-6ff8bc444f-t7h49           | Running | 10.42.2.20 | ReplicaSet | agent1      | 2.84m     | 70.71Mi      | filebeat-container:0           | filebeat-oss:23.07.1      |
zeek-offline-deployment-844f4865bd-g2sdm       | Running | 10.42.2.21 | ReplicaSet | agent1      | 0.17m     | 41.92Mi      | zeek-offline-container:0       | zeek:23.07.1              |
logstash-deployment-6fbc9fdcd5-hwx8s           | Running | 10.42.2.22 | ReplicaSet | agent1      | 85.55m    | 2.91Gi       | logstash-container:0           | logstash-oss:23.07.1      |
netbox-deployment-cdcff4977-hbbw5              | Running | 10.42.2.23 | ReplicaSet | agent1      | 807.64m   | 702.86Mi     | netbox-container:0             | netbox:23.07.1            |
suricata-offline-deployment-6ccdb89478-z5696   | Running | 10.42.2.19 | ReplicaSet | agent1      | 0.22m     | 34.88Mi      | suricata-offline-container:0   | suricata:23.07.1          |
dashboards-deployment-69b5465db-vz88g          | Running | 10.42.1.14 | ReplicaSet | agent2      | 0.94m     | 100.12Mi     | dashboards-container:0         | dashboards:23.07.1        |
netbox-redis-cache-deployment-5f77d47b8b-z7t2z | Running | 10.42.1.15 | ReplicaSet | agent2      | 3.57m     | 7.36Mi       | netbox-redis-cache-container:0 | redis:23.07.1             |
suricata-live-deployment-6494c77759-9rlnt      | Running | 10.42.1.16 | ReplicaSet | agent2      | 0.02m     | 9.69Mi       | suricata-live-container:0      | suricata:23.07.1          |
freq-deployment-cfd84fd97-dnngf                | Running | 10.42.1.17 | ReplicaSet | agent2      | 0.2m      | 26.36Mi      | freq-container:0               | freq:23.07.1              |
arkime-deployment-56999cdd66-s98pp             | Running | 10.42.1.18 | ReplicaSet | agent2      | 4.15m     | 113.07Mi     | arkime-container:0             | arkime:23.07.1            |
pcap-monitor-deployment-594ff674c4-fsm7m       | Running | 10.42.1.19 | ReplicaSet | agent2      | 1.24m     | 48.44Mi      | pcap-monitor-container:0       | pcap-monitor:23.07.1      |
pcap-capture-deployment-7c8bf6957-jzpzn        | Running | 10.42.1.20 | ReplicaSet | agent2      | 0.02m     | 9.64Mi       | pcap-capture-container:0       | pcap-capture:23.07.1      |
netbox-postgres-deployment-5879b8dffc-kkt56    | Running | 10.42.1.21 | ReplicaSet | agent2      | 70.91m    | 33.02Mi      | netbox-postgres-container:0    | postgresql:23.07.1        |
htadmin-deployment-6fc46888b9-sq6ln            | Running | 10.42.1.23 | ReplicaSet | agent2      | 0.14m     | 30.53Mi      | htadmin-container:0            | htadmin:23.07.1           |
netbox-redis-deployment-5bcd8f6c96-j5xpf       | Running | 10.42.1.24 | ReplicaSet | agent2      | 1.46m     | 7.34Mi       | netbox-redis-container:0       | redis:23.07.1             |
nginx-proxy-deployment-69fcc4968d-f68tq        | Running | 10.42.1.22 | ReplicaSet | agent2      | 0.31m     | 22.63Mi      | nginx-proxy-container:0        | nginx-proxy:23.07.1       |
opensearch-deployment-75498799f6-4zmwd         | Running | 10.42.1.25 | ReplicaSet | agent2      | 89.8m     | 11.03Gi      | opensearch-container:0         | opensearch:23.07.1        |
```

The other control scripts (`stop`, `restart`, `logs`, etc.) work in a similar manner as in a Docker-based deployment. One notable difference is the `wipe` script: data on PersistentVolume storage cannot be deleted by `wipe`. It must be deleted manually on the storage media underlying the PersistentVolumes.

Malcolm's control scripts require the [official Python 3 client library for Kubernetes](https://github.com/kubernetes-client/python) to configure and run Malcolm with Kubernetes. It is also recommended to install **[stern](https://github.com/stern/stern)**, which is used by the `./scripts/logs` script to tail Malcolm's container logs.

# <a name="Example"></a> Deployment Example

Here is a basic step-by-step example illustrating how to deploy Malcolm with Kubernetes. For the sake of simplicity, this example uses Vagrant (see [kubernetes/vagrant/Vagrantfile]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/Vagrantfile)) to create a virtualized Kubernetes cluster with one control plane node and two worker nodes. It assumes users have downloaded and extracted the [release tarball]({{ site.github.repository_url }}/releases) or used `./scripts/malcolm_appliance_packager.sh` to package up the files needed to run Malcolm.

```
$ ls -l
total 45,056
drwxr-xr-x 2 user user      6 Apr 24 14:35 arkime-logs
drwxr-xr-x 2 user user      6 Apr 24 14:35 arkime-raw
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
-rw-r--r-- 1 user user      2 Apr 24 14:35 net-map.json
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

Run `./scripts/configure` and answer the questions to configure Malcolm. For an in-depth treatment of these configuration questions, see the **Configuration** section in **[End-to-end Malcolm and Hedgehog Linux ISO Installation](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)**:


```
$ ./scripts/configure -f /path/to/kubeconfig.yaml

Malcolm processes will run as UID 1000 and GID 1000. Is this OK? (Y/n): y

Should Malcolm use and maintain its own OpenSearch instance? (Y/n): y

Compress OpenSearch index snapshots? (y/N): n

Forward Logstash logs to a secondary remote OpenSearch instance? (y/N): n

Setting 16g for OpenSearch and 3g for Logstash. Is this OK? (Y/n): y

Setting 6 workers for Logstash pipelines. Is this OK? (Y/n): y

Require encrypted HTTPS connections? (Y/n): y

1: Basic
2: Lightweight Directory Access Protocol (LDAP)
3: None
Select authentication method (Basic): 1

Delete the oldest indices when the database exceeds a certain size? (y/N): y

Enter index threshold (e.g., 250GB, 1TB, 60%, etc.): 250G

Determine oldest indices by name (instead of creation time)? (Y/n): y

Should Arkime delete PCAP files based on available storage (see https://arkime.com/faq#pcap-deletion)? (y/N): y

Automatically analyze all PCAP files with Suricata? (Y/n): y

Download updated Suricata signatures periodically? (y/N): y

Automatically analyze all PCAP files with Zeek? (Y/n): y

Should Malcolm use "best guess" to identify potential OT/ICS traffic with Zeek? (y/N): n

Perform reverse DNS lookup locally for source and destination IP addresses in logs? (y/N): n

Perform hardware vendor OUI lookups for MAC addresses? (Y/n): y

Perform string randomness scoring on some fields? (Y/n): y

Use default field values for Filebeat TCP listener? (Y/n): y

Enable file extraction with Zeek? (y/N): y
1: none
2: known
3: mapped
4: all
5: interesting

Select file extraction behavior (none): 5
1: quarantined
2: all
3: none
Select file preservation behavior (quarantined): 1

Expose web interface for downloading preserved files? (y/N): y

Enter AES-256-CBC encryption password for downloaded preserved files (or leave blank for unencrypted): quarantined

Scan extracted files with ClamAV? (Y/n): y

Scan extracted files with Yara? (Y/n): y

Scan extracted PE files with Capa? (Y/n): y

Lookup extracted file hashes with VirusTotal? (y/N): n

Download updated file scanner signatures periodically? (y/N): y

Should Malcolm run and maintain an instance of NetBox, an infrastructure resource modeling tool? (y/N): y

Should Malcolm enrich network traffic using NetBox? (Y/n): y

Should Malcolm automatically populate NetBox inventory based on observed network traffic? (/N): n

Specify default NetBox site name: Malcolm

Enable dark mode for OpenSearch Dashboards? (Y/n): y

Malcolm has been installed to /home/user/Malcolm. See README.md for more information.

Scripts for starting and stopping Malcolm and changing authentication-related settings can be found in /home/user/Malcolm/scripts.
```

Run `./scripts/auth_setup` and answer the questions to [configure authentication](authsetup.md#AuthSetup):

```
$ ./scripts/auth_setup -f /path/to/kubeconfig.yaml

1: all - Configure all authentication-related settings
2: admin - Store administrator username/password for local Malcolm access
3: webcerts - (Re)generate self-signed certificates for HTTPS access
4: fwcerts - (Re)generate self-signed certificates for a remote log forwarder
5: remoteos - Configure remote primary or secondary OpenSearch instance
6: email - Store username/password for email alert sender account
7: netbox - (Re)generate internal passwords for NetBox
8: txfwcerts - Transfer self-signed client certificates to a remote log forwarder

Configure Authentication (all): 1

Store administrator username/password for local Malcolm access? (Y/n): y

Administrator username: analyst
analyst password:
analyst password (again):

Additional local accounts can be created at https://localhost/auth/ when Malcolm is running

(Re)generate self-signed certificates for HTTPS access? (Y/n): y

(Re)generate self-signed certificates for a remote log forwarder? (Y/n): y

Configure remote primary or secondary OpenSearch instance? (y/N): n

Store username/password for email alert sender account? (y/N): n

(Re)generate internal passwords for NetBox? (Y/n): y

Transfer self-signed client certificates to a remote log forwarder? (y/N): n

```

Next, copy `./kubernetes/01-volumes-nfs.yml.example` to `./kubernetes/01-volumes.yml` and edit that file to define the [required PersistentVolumeClaims](#PVC) there.

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

Malcolm services can be accessed via the following URLs:
------------------------------------------------------------------------------
  - Arkime: https://192.168.56.10/
  - OpenSearch Dashboards: https://192.168.56.10/dashboards/
  - PCAP upload (web): https://192.168.56.10/upload/
  - NetBox: https://192.168.56.10/netbox/
  - Account management: https://192.168.56.10/auth/
  - Documentation: https://192.168.56.10/readme/

```

Check the status of the Malcolm deployment with `./scripts/status`:

```
$ ./scripts/status -f /path/to/kubeconfig.yaml

Node Name | Hostname | IP            | Provider ID | Instance Type | Total CPU | CPU Usage | Percent CPU | Total Memory | Memory Usage | Total Storage | Current Pods |
server    | server   | 192.168.56.10 | server      | k3s           | 4000m     | 47.03m    | 1.18%       | 7.77Gi       | 1.14Gi       | 61.28Gi       | 7            |
agent1    | agent1   | 192.168.56.11 | agent1      | k3s           | 6000m     | 3677.42m  | 61.29%      | 19.55Gi      | 4.95Gi       | 61.28Gi       | 12           |
agent2    | agent2   | 192.168.56.12 | agent2      | k3s           | 6000m     | 552.71m   | 9.21%       | 19.55Gi      | 13.27Gi      | 61.28Gi       | 12           |

Pod Name                                       | State   | Pod IP     | Pod Kind   | Worker Node | CPU Usage | Memory Usage | Container Name:Restarts        | Container Image              |
netbox-redis-cache-deployment-5f77d47b8b-jr9nt | Running | 10.42.2.6  | ReplicaSet | agent2      | 1.89m     | 7.24Mi       | netbox-redis-cache-container:0 | redis:23.07.1             |
netbox-redis-deployment-5bcd8f6c96-bkzmh       | Running | 10.42.2.5  | ReplicaSet | agent2      | 1.62m     | 7.52Mi       | netbox-redis-container:0       | redis:23.07.1             |
dashboards-helper-deployment-69dc54f6b6-ks7ps  | Running | 10.42.2.4  | ReplicaSet | agent2      | 12.95m    | 40.75Mi      | dashboards-helper-container:0  | dashboards-helper:23.07.1 |
freq-deployment-cfd84fd97-5bwp6                | Running | 10.42.2.8  | ReplicaSet | agent2      | 0.11m     | 26.33Mi      | freq-container:0               | freq:23.07.1              |
pcap-capture-deployment-7c8bf6957-hkvkn        | Running | 10.42.2.12 | ReplicaSet | agent2      | 0.02m     | 9.21Mi       | pcap-capture-container:0       | pcap-capture:23.07.1      |
nginx-proxy-deployment-69fcc4968d-m57rz        | Running | 10.42.2.10 | ReplicaSet | agent2      | 0.91m     | 22.72Mi      | nginx-proxy-container:0        | nginx-proxy:23.07.1       |
htadmin-deployment-6fc46888b9-vpt7l            | Running | 10.42.2.7  | ReplicaSet | agent2      | 0.16m     | 30.21Mi      | htadmin-container:0            | htadmin:23.07.1           |
opensearch-deployment-75498799f6-5v92w         | Running | 10.42.2.13 | ReplicaSet | agent2      | 139.2m    | 10.86Gi      | opensearch-container:0         | opensearch:23.07.1        |
zeek-live-deployment-64b69d4b6f-fcb6n          | Running | 10.42.2.9  | ReplicaSet | agent2      | 0.02m     | 109.55Mi     | zeek-live-container:0          | zeek:23.07.1              |
dashboards-deployment-69b5465db-kgsqk          | Running | 10.42.2.3  | ReplicaSet | agent2      | 14.98m    | 108.85Mi     | dashboards-container:0         | dashboards:23.07.1        |
arkime-deployment-56999cdd66-xxpw9             | Running | 10.42.2.11 | ReplicaSet | agent2      | 208.95m   | 78.42Mi      | arkime-container:0             | arkime:23.07.1            |
api-deployment-6f4686cf59-xt9md                | Running | 10.42.1.3  | ReplicaSet | agent1      | 0.14m     | 56.88Mi      | api-container:0                | api:23.07.1               |
netbox-postgres-deployment-5879b8dffc-lb4qm    | Running | 10.42.1.6  | ReplicaSet | agent1      | 141.2m    | 48.02Mi      | netbox-postgres-container:0    | postgresql:23.07.1        |
pcap-monitor-deployment-594ff674c4-fwq7g       | Running | 10.42.1.12 | ReplicaSet | agent1      | 3.93m     | 46.44Mi      | pcap-monitor-container:0       | pcap-monitor:23.07.1      |
suricata-offline-deployment-6ccdb89478-j5fgj   | Running | 10.42.1.10 | ReplicaSet | agent1      | 10.42m    | 35.12Mi      | suricata-offline-container:0   | suricata:23.07.1          |
suricata-live-deployment-6494c77759-rpt48      | Running | 10.42.1.8  | ReplicaSet | agent1      | 0.01m     | 9.62Mi       | suricata-live-container:0      | suricata:23.07.1          |
netbox-deployment-cdcff4977-7ns2q              | Running | 10.42.1.7  | ReplicaSet | agent1      | 830.47m   | 530.7Mi      | netbox-container:0             | netbox:23.07.1            |
zeek-offline-deployment-844f4865bd-7x68b       | Running | 10.42.1.9  | ReplicaSet | agent1      | 1.44m     | 43.66Mi      | zeek-offline-container:0       | zeek:23.07.1              |
filebeat-deployment-6ff8bc444f-pdgzj           | Running | 10.42.1.11 | ReplicaSet | agent1      | 0.78m     | 75.25Mi      | filebeat-container:0           | filebeat-oss:23.07.1      |
file-monitor-deployment-855646bd75-nbngq       | Running | 10.42.1.4  | ReplicaSet | agent1      | 1.69m     | 1.46Gi       | file-monitor-container:0       | file-monitor:23.07.1      |
upload-deployment-586568844b-9s7f5             | Running | 10.42.1.13 | ReplicaSet | agent1      | 0.14m     | 29.62Mi      | upload-container:0             | file-upload:23.07.1       |
logstash-deployment-6fbc9fdcd5-2hhx8           | Running | 10.42.1.5  | ReplicaSet | agent1      | 3236.29m  | 357.36Mi     | logstash-container:0           | logstash-oss:23.07.1      |
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

Deploying Malcolm with Kubernetes is a new (and still somewhat experimental) feature, and does not yet support the full range of Malcolm features. Development around these features is [ongoing](https://github.com/idaholab/Malcolm/issues?q=is%3Aissue+is%3Aopen+kubernetes). Some of the notable features that are still a work in progress for Kubernetes deployment include:

## <a name="FutureLiveCap"></a> Live Traffic Analysis

For now, network traffic artifacts for analysis are provided to a Malcolm deployment on Kubernetes via [forwarding](malcolm-hedgehog-e2e-iso-install.md#HedgehogConfigForwarding) from a remote instance of [Hedgehog Linux](hedgehog.md) or via PCAP [upload](upload.md#Upload). [Future work](https://github.com/idaholab/Malcolm/issues/175) is needed to design and implement monitoring of network traffic in the cloud.

## <a name="FutureScaleOut"></a> Horizontal Scaling

For now, the Malcolm services running in Kubernetes are configured with `replicas: 1`. There is [more investigation and development](https://github.com/idaholab/Malcolm/issues/182) needed to ensure Malcolm's containers work correctly when horizontally scaled.

## <a name="FutureHelmChart"></a> Helm Chart

For now, Malcolm's Kubernetes deployment is managed via standard [Kubernetes manifests]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/). The Malcolm developers need to [look into](https://github.com/idaholab/Malcolm/issues/187) what a Malcolm Helm chart would look like and how it would fit in with the [deployment scripts](https://github.com/idaholab/Malcolm/issues/172) for [configuring](#Config) and [running](#Running) Malcolm, if at all.
