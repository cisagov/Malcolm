# <a name="AWS"></a>Deploying Malcolm on Amazon Web Services (AWS)

* [Deploying Malcolm on Amazon Web Services (AWS)](#AWS)
    - [Installing prerequisites](#AWSPrereqInstall)
    - [Amazon EC2 Instance Types](#AWSInstanceSizing)
    - [Installing Malcolm in an EC2 instance](#AWSEC2)
        + [Instance creation](#AWSEC2Instance)
        + [Malcolm setup](#AWSEC2Install)
        + [Running Malcolm](#AWSEC2Run)
    - [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](#KubernetesEKS)
        + [Deploying with EKS](#AWSEKS)
        + [Deploying with EKS Auto Mode](#AWSEKSAuto)
        + [Common Steps for EKS Deployments](#AWSEKSCommon)
    - [Generating a Malcolm Amazon Machine Image (AMI)](#AWSAMI)
        + [Launching an EC2 instance from the Malcolm AMI](#AWSAMILaunch)
        + [Using MFA](#AWSAMIMFA)
* [Attribution and Disclaimer](#AWSAttribution)

## <a name="AWSPrereqInstall"></a>Installing prerequisites

The sections below make use of various command line tools. Installation may vary from platform to platform; however, this section gives some basic examples of how to install these tools in Linux environments. Not every guide in this document requires each of the following commands.

* [`aws`, the AWS Command Line Interface](https://aws.amazon.com/cli/)

```bash
$ curl -fsSL \
    -o /tmp/awscli.zip \
    "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip"
$ unzip -d /tmp /tmp/awscli.zip
…
$ sudo /tmp/aws/install
You can now run: /usr/local/bin/aws --version
$ aws --version
aws-cli/2.26.2 Python/3.13.2 Linux/6.1.0-32-amd64 exe/x86_64.ubuntu.24
```

* [`eksctl`, the official CLI for Amazon EKS](https://eksctl.io/)

```bash
$ curl -fsSL \
    -o /tmp/eksctl.tar.gz \
    "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_Linux_$(uname -m | sed 's/^x86_64$/amd64/').tar.gz"
$ tar -xzf /tmp/eksctl.tar.gz -C /tmp && rm /tmp/eksctl.tar.gz
$ sudo mv /tmp/eksctl /usr/local/bin/
$ eksctl version
0.207.0
```

* [`kubectl`, the Kubernetes command line tool](https://kubernetes.io/docs/reference/kubectl/)

```bash
$ curl -fsSL \
    -o /tmp/kubectl \
    "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$(uname -m | sed 's/^x86_64$/amd64/' | sed 's/^aarch64$/arm64/')/kubectl"
$ chmod 755 /tmp/kubectl
$ sudo mv /tmp/kubectl /usr/local/bin/
$ kubectl version
Client Version: v1.32.3
```

* [`helm`, the package manager for Kubernetes](https://helm.sh/)

```bash
$ curl -fsSL \
    -o /tmp/get_helm.sh \
    https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
$ chmod 700 /tmp/get_helm.sh
$ /tmp/get_helm.sh
$ helm version
version.BuildInfo{Version:"v3.17.3", GitCommit:"e4da49785aa6e6ee2b86efd5dd9e43400318262b", GitTreeState:"clean", GoVersion:"go1.23.7"}
```

* [`packer`, a tool to build automated machine images](https://developer.hashicorp.com/packer)

```bash
$ PACKER_VERSION="$(curl -fsSL 'https://releases.hashicorp.com/packer/' | grep -Po 'href="/packer/[^"]+"' | sort --version-sort | cut -d'/' -f3 | tail -n 1)"
$ curl -fsSL \
    -o /tmp/packer.zip \
    "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_$(uname -m | sed 's/^x86_64$/amd64/' | sed 's/^aarch64$/arm64/').zip"
$ unzip -d /tmp /tmp/packer.zip
$ chmod 755 /tmp/packer
$ sudo mv /tmp/packer /usr/local/bin/
$ packer --version
Packer v1.12.0
```

## <a name="AWSInstanceSizing"></a>Amazon EC2 Instance Types

Malcolm is a resource-intensive tool: instance types should meet Malcolm's [minimum system requirements](system-requirements.md#SystemRequirements). A few AWS EC2 instance types meeting recommended minimum requirements include:

* amd64
    - [c5.9xlarge or c5.4xlarge](https://aws.amazon.com/ec2/instance-types/#Compute_Optimized) (compute optimized); [m6a.4xlarge or t3.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose) (general purpose)
* arm64
    - [c6g.8xlarge or c6g.4xlarge](https://aws.amazon.com/ec2/instance-types/#Compute_Optimized) (compute optimized); [m6g.4xlarge or t4g.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose) (general purpose)

## <a name="AWSEC2"></a>Installing Malcolm in an EC2 instance

This section outlines the process of using the [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/) to instantiate an [EC2](https://aws.amazon.com/ec2/) instance running Malcolm. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSEC2Instance"></a> Instance creation

These steps are to be run on a Linux, Windows, or macOS system in a command line environment with the [AWS Command Line Interface (AWS CLI)](https://aws.amazon.com/cli/) installed. Users should adjust these steps to their own use cases in terms of naming resources, setting security policies, etc.

* Create a [key pair for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html)

```bash
$ aws ec2 create-key-pair \
    --key-name malcolm-key \
    --query "KeyMaterial" \
    --output text > ./malcolm-key.pem

$ chmod 600 ./malcolm-key.pem
```

* Create a [security group for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-sg \
    --description "Malcolm SG"
…
```

* Set inbound [security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
    - These rules will allow SSH and HTTPS access from the address(es) specified
    - Replace `#.#.#.#` with the public IP address(es) (i.e., addresses which will be allowed to connect to the Malcolm instance via SSH and HTTPS) in the following commands

```bash
$ PUBLIC_IP=#.#.#.#

$ for PORT in 22 443; do \
    aws ec2 authorize-security-group-ingress \
        --group-name malcolm-sg \
        --protocol tcp \
        --port $PORT \
        --cidr $PUBLIC_IP/32; \
done
…
```

* [Get a list](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html) of Ubuntu Minimal [AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
    - This example uses Ubuntu as the base operating system for the EC2 instance
    - `099720109477` is the account number for Canonical, the producer of Ubuntu
    - Replace `ARCH` with the desired architecture (`amd64` or `arm64`) in the following command
    - Make note of the most recent AMI ID for the next step

```bash
$ aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu-minimal/images/*/ubuntu-noble-24.04-ARCH*" \
    --query "Images[*].[Name,ImageId,CreationDate]" \
    --output text | sort
…
```

* Launch selected AMI
    - Replace `INSTANCE_TYPE` with the desired instance type in the following command
        + See [EC2 Instance Types](#AWSInstanceSizing) for suggestions
    - Replace `AMI_ID` with the AMI ID from the previous step in the following command
    - The size of the storage volume will vary depending on the amount of data users plan to process and retain in Malcolm. The example here uses 100 GiB; users should adjust as needed for their specific use case.

```bash
$ aws ec2 run-instances \
    --image-id AMI_ID \
    --instance-type INSTANCE_TYPE \
    --key-name malcolm-key \
    --security-group-ids malcolm-sg \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":100,\"VolumeType\":\"gp3\"}}]" \
    --count 1 \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=Malcolm}]"
…
```

* Get [instance details](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html) and check its status

```bash
$ aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=Malcolm" \
    --query "Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name}" \
    --output table
…
```

### <a name="AWSEC2Install"></a> Malcolm setup

The next steps are to be run as the `ubuntu` user *inside* the EC2 instance, either connected via [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or via SSH using the key pair created in the first step.

* Install `curl`, `unzip`, and `python3`

```bash
$ sudo apt-get -y update
…
$ sudo apt-get -y install --no-install-recommends \
    curl \
    unzip \
    python3 \
    python3-dialog \
    python3-dotenv \
    python3-pip \
    python3-ruamel.yaml
…
```

* [Download](download.md#DownloadDockerImages) the latest Malcolm release ZIP file
    - Navigate a web browser to the [Malcolm releases page]({{ site.github.repository_url }}/releases/latest) and identify the version number of the latest Malcolm release (`{{ site.malcolm.version }}` is used in this example).

```bash
$ curl -OJsSLf https://github.com/cisagov/Malcolm/releases/latest/download/malcolm-{{ site.malcolm.version }}-docker_install.zip

$ ls -l malcolm*.zip
-rw-rw-r-- 1 ubuntu ubuntu 191053 Apr 10 14:26 malcolm-{{ site.malcolm.version }}-docker_install.zip
```

* Extract the Malcolm release ZIP file

```bash
$ unzip malcolm-{{ site.malcolm.version }}-docker_install.zip
Archive:  malcolm-{{ site.malcolm.version }}-docker_install.zip
  inflating: install.py
  inflating: malcolm_20250401_225238_df27028c.README.txt
  inflating: malcolm_20250401_225238_df27028c.tar.gz
  inflating: malcolm_common.py
  inflating: malcolm_kubernetes.py
  inflating: malcolm_utils.py
```

* Run `install.py`.
    - Malcolm's installation and configuration scripts will guide users through the setup process.
    - Use the following resources to answer the installation and configuration questions:
        + [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        + [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)

* `install.py` part 1: Docker installation and system configuration
    - The [installer script](malcolm-config.md#ConfigAndTuning) will install and configure Docker and Docker Compose, and make necessary changes to system configuration.

```bash
"docker info" failed, attempt to install Docker? (Y / n): y

Attempt to install Docker using official repositories? (Y / n): y

Apply recommended system tweaks automatically without asking for confirmation? y
…
```

* `install.py` part 2: Malcolm configuration
    - Users should answer the remaining [configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) as they apply to their use case.

* Pull Malcolm container images
    - Answer **Yes** when prompted to **Pull Malcolm images?**
    - Pulling the container images may take several minutes.

* Reboot the instance (`sudo reboot`)
    - This allows the changes to system configuration to take effect
    - After a few minutes, reconnect via Session Manager or SSH

* Set up authentication
    - [Configure authentication](authsetup.md#AuthSetup) using `./scripts/auth_setup` in the Malcolm installation directory.
    - [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the remaining prompts.

```bash
$ cd ~/malcolm

$ ./scripts/auth_setup

all        Configure all authentication-related settings
…
```

### <a name="AWSEC2Run"></a> Running Malcolm

* Start Malcolm
    - Running `./scripts/start` in the Malcolm installation directory will [start Malcolm](running.md#Starting).
    - Malcolm takes a few minutes to start. During this time users may see text scroll past from the containers' logs that look like error messages. This is normal while Malcolm's services synchronize among themselves.
    - Once Malcolm is running, the start script will output **Started Malcolm** and return to the command prompt.

```bash
$ cd ~/malcolm

$ ./scripts/start
…
logstash-1 | [2025-04-10T15:03:28,294][INFO ][logstash.agent ] Pipelines running {:count=>6, :running_pipelines=>[:"malcolm-input", :"malcolm-output", :"malcolm-suricata", :"malcolm-enrichment", :"malcolm-beats", :"malcolm-zeek"], :non_running_pipelines=>[]}

Started Malcolm

Malcolm services can be accessed at https://<IP address>/
------------------------------------------------------------------------------
```

* Check Malcolm's status
    - Running `./scripts/status` in the Malcolm installation directory will display the status of Malcolm's services.

```bash
$ cd ~/malcolm

$ ./scripts/status
NAME                          IMAGE                                                      COMMAND                  SERVICE             CREATED         STATUS                   PORTS
malcolm-api-1                 ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}-arm64                 "/usr/bin/tini -- /u…"   api                 7 minutes ago   Up 7 minutes (healthy)   5000/tcp
malcolm-arkime-1              ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   arkime              7 minutes ago   Up 7 minutes (healthy)   8000/tcp, 8005/tcp, 8081/tcp
malcolm-arkime-live-1         ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   arkime-live         7 minutes ago   Up 7 minutes (healthy)
malcolm-dashboards-1          ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}-arm64          "/usr/bin/tini -- /u…"   dashboards          7 minutes ago   Up 7 minutes (healthy)   5601/tcp
malcolm-dashboards-helper-1   ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}-arm64   "/usr/bin/tini -- /u…"   dashboards-helper   7 minutes ago   Up 7 minutes (healthy)   28991/tcp
malcolm-file-monitor-1        ghcr.io/idaholab/malcolm/file-monitor:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   file-monitor        7 minutes ago   Up 7 minutes (healthy)   3310/tcp, 8440/tcp
malcolm-filebeat-1            ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   filebeat            7 minutes ago   Up 7 minutes (healthy)
malcolm-freq-1                ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   freq                7 minutes ago   Up 7 minutes (healthy)   10004/tcp
malcolm-htadmin-1             ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}-arm64             "/usr/bin/tini -- /u…"   htadmin             7 minutes ago   Up 7 minutes (healthy)   80/tcp
malcolm-keycloak-1            ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   keycloak            7 minutes ago   Up 7 minutes (healthy)   8080/tcp, 8443/tcp, 9000/tcp
malcolm-logstash-1            ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   logstash            7 minutes ago   Up 7 minutes (healthy)   5044/tcp, 9001/tcp, 9600/tcp
malcolm-netbox-1              ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   netbox              7 minutes ago   Up 7 minutes (healthy)   9001/tcp
malcolm-nginx-proxy-1         ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}-arm64         "/sbin/tini -- /usr/…"   nginx-proxy         7 minutes ago   Up 7 minutes (healthy)   0.0.0.0:443->443/tcp
malcolm-opensearch-1          ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}-arm64          "/usr/bin/tini -- /u…"   opensearch          7 minutes ago   Up 7 minutes (healthy)   9200/tcp, 9300/tcp, 9600/tcp, 9650/tcp
malcolm-pcap-capture-1        ghcr.io/idaholab/malcolm/pcap-capture:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   pcap-capture        7 minutes ago   Up 7 minutes (healthy)
malcolm-pcap-monitor-1        ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   pcap-monitor        7 minutes ago   Up 7 minutes (healthy)   30441/tcp
malcolm-postgres-1            ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}-arm64          "/sbin/tini -- /usr/…"   postgres            7 minutes ago   Up 7 minutes (healthy)   5432/tcp
malcolm-redis-1               ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}-arm64               "/sbin/tini -- /usr/…"   redis               7 minutes ago   Up 7 minutes (healthy)   6379/tcp
malcolm-redis-cache-1         ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}-arm64               "/sbin/tini -- /usr/…"   redis-cache         7 minutes ago   Up 7 minutes (healthy)   6379/tcp
malcolm-suricata-1            ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   suricata            7 minutes ago   Up 7 minutes (healthy)
malcolm-suricata-live-1       ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   suricata-live       7 minutes ago   Up 7 minutes (healthy)
malcolm-upload-1              ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}-arm64         "/usr/bin/tini -- /u…"   upload              7 minutes ago   Up 7 minutes (healthy)   22/tcp, 80/tcp
malcolm-zeek-1                ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   zeek                7 minutes ago   Up 7 minutes (healthy)
malcolm-zeek-live-1           ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   zeek-live           7 minutes ago   Up 7 minutes (healthy)
```

* Connect to Malcolm's [web interface](quickstart.md#UserInterfaceURLs)
    - Navigate a web browser to the IP address of the instance using HTTPS
    - Log in with the credentials specified when setting up authentication
    - See the Malcolm [Learning Tree](https://github.com/cisagov/Malcolm/wiki/Learning) and [documentation](README.md) for next steps.

## <a name="KubernetesEKS"></a>Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)

This section outlines the process of setting up a cluster on [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) using [Amazon Web Services (AWS)](https://aws.amazon.com/).

These instructions assume good working knowledge of AWS and EKS. Good documentation resources can be found in the [AWS documentation](https://docs.aws.amazon.com/index.html), the [EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html
) and the [EKS Workshop](https://www.eksworkshop.com/).

This section covers two deployment options: deploying Malcolm in a standard Kubernetes cluster on Amazon EKS, and deploying Malcolm with [EKS auto mode](https://aws.amazon.com/eks/auto-mode/).

* The first step in each of these respective procedures is to download Malcolm.

    * Install some dependencies (this will vary by OS distribution, adjust as needed)

    ```bash
    $ sudo apt-get -y update
    …
    $ sudo apt-get -y install --no-install-recommends \
        apache2-utils \
        curl \
        openssl \
        python3 \
        python3-dialog \
        python3-dotenv \
        python3-kubernetes \
        python3-pip \
        python3-ruamel.yaml \
        unzip \
        xz-utils
    …
    ```

    * [Download](download.md#DownloadDockerImages) the latest Malcolm release ZIP file
        - Navigate a web browser to the [Malcolm releases page]({{ site.github.repository_url }}/releases/latest) and identify the version number of the latest Malcolm release (`{{ site.malcolm.version }}` is used in this example), and either download the Malcolm release ZIP file there or use `curl` to do so:

    ```bash
    $ curl -OJsSLf https://github.com/cisagov/Malcolm/releases/latest/download/malcolm-{{ site.malcolm.version }}-docker_install.zip

    $ ls -l malcolm*.zip
    -rw-rw-r-- 1 ubuntu ubuntu 191053 Apr 10 14:26 malcolm-{{ site.malcolm.version }}-docker_install.zip
    ```

    * Extract the Malcolm release ZIP file

    ```bash
    $ unzip malcolm-{{ site.malcolm.version }}-docker_install.zip
    Archive:  malcolm-{{ site.malcolm.version }}-docker_install.zip
      inflating: install.py
      inflating: malcolm_20250401_225238_df27028c.README.txt
      inflating: malcolm_20250401_225238_df27028c.tar.gz
      inflating: malcolm_common.py
      inflating: malcolm_kubernetes.py
      inflating: malcolm_utils.py
    ```

### <a name="AWSEKS"></a>Deploying with EKS

* Create a [file](https://eksctl.io/usage/creating-and-managing-clusters/#using-config-files) called `cluster.yaml` and customize as needed (see [EC2 Instance Types](#AWSInstanceSizing) for suggestions for `instanceType`)

```yml
# cluster.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: malcolm-cluster
  region: us-east-1

nodeGroups:
  - name: private-nodes
    instanceType: t3.2xlarge
    desiredCapacity: 2
    minSize: 1
    maxSize: 3
    privateNetworking: true
```

* [Create the cluster](https://eksctl.io/usage/creating-and-managing-clusters/) using `eksctl`

```bash
$ eksctl create cluster -f cluster.yaml
…
```

* Enable [OIDC provider](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html)

```bash
$ eksctl utils associate-iam-oidc-provider \
    --region=us-east-1 --cluster=malcolm-cluster --approve
…
```

* Create namespace

```bash
$ kubectl create namespace malcolm
…
```

* Proceed to [Common Steps for EKS Deployments](#AWSEKSCommon)

### <a name="AWSEKSAuto"></a> Deploying with [EKS Auto Mode](https://aws.amazon.com/eks/auto-mode/)

* Create a [file](https://eksctl.io/usage/creating-and-managing-clusters/#using-config-files) called `cluster.yaml` and customize as needed

```yml
# cluster.yaml
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: malcolm-cluster
  region: us-east-1

addonsConfig:
  disableDefaultAddons: true

autoModeConfig:
  enabled: true
```

* [Create the cluster](https://eksctl.io/usage/creating-and-managing-clusters/) using `eksctl`

```bash
$ eksctl create cluster -f cluster.yaml
…
```

* Enable [OIDC provider](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html)

```bash
$ eksctl utils associate-iam-oidc-provider \
    --region=us-east-1 --cluster=malcolm-cluster --approve
…
```

* Deploy [metrics-server](https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html):

```bash
$ kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
…
```

* Create namespace

```bash
$ kubectl create namespace malcolm
…
```

* Proceed to [Common Steps for EKS Deployments](#AWSEKSCommon)

### <a name="AWSEKSCommon"></a> Common Steps for EKS Deployments

* Configure Malcolm
    * `./install.py -f "${KUBECONFIG:-$HOME/.kube/config}"`
    * Malcolm's configuration scripts will guide users through the setup process.
    * Use the following resources to answer the installation and configuration questions:
        * [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        * [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)
    * Configure [authentication](authsetup.md#AuthSetup)
        * `./Malcolm/scripts/auth_setup -f "${KUBECONFIG:-$HOME/.kube/config}"`
        * [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the prompts.

* Create [IAM policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html) for [EFS CSI driver](https://github.com/kubernetes-sigs/aws-efs-csi-driver)

```bash
$ aws iam create-policy \
  --policy-name AmazonEKS_EFS_CSI_Driver_Policy \
  --policy-document "$(curl -fsSL 'https://raw.githubusercontent.com/kubernetes-sigs/aws-efs-csi-driver/refs/heads/master/docs/iam-policy-example.json')"
…
```

* Create [service account](https://eksctl.io/usage/iamserviceaccounts/) for EFS CSI driver

```bash
$ eksctl create iamserviceaccount \
    --cluster malcolm-cluster \
    --namespace kube-system \
    --name efs-csi-controller-sa \
    --attach-policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AmazonEKS_EFS_CSI_Driver_Policy \
    --approve \
    --override-existing-serviceaccounts \
    --region us-east-1
…
```

* Create IAM policy for [AWS load balancer](https://github.com/kubernetes-sigs/aws-load-balancer-controller)

```bash
$ aws iam create-policy \
  --policy-name AmazonAWS_Load_Balancer_Controller_Policy \
  --policy-document "$(curl -fsSL 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json')"
…
```

* Create service account for AWS load balancer

```bash
$ eksctl create iamserviceaccount \
    --cluster malcolm-cluster \
    --namespace kube-system \
    --name aws-load-balancer-controller \
    --attach-policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AmazonAWS_Load_Balancer_Controller_Policy \
    --approve \
    --override-existing-serviceaccounts \
    --region us-east-1
…
```

* Install [AWS EFS CSI Driver](https://github.com/kubernetes-sigs/aws-efs-csi-driver?tab=readme-ov-file#amazon-efs-csi-driver) via Helm

```bash
$ helm repo add efs-csi-driver https://kubernetes-sigs.github.io/aws-efs-csi-driver
…
$ helm repo update
…
$ helm install efs-csi-driver efs-csi-driver/aws-efs-csi-driver \
  -n kube-system \
  --set controller.serviceAccount.create=false \
  --set controller.serviceAccount.name=efs-csi-controller-sa
…
```

* Create [EFS file system](https://docs.aws.amazon.com/efs/latest/ug/whatisefs.html)

```bash
$ aws efs create-file-system \
    --creation-token malcolm-efs \
    --encrypted \
    --region us-east-1 \
    --tags "Key=Name,Value=malcolm-efs" \
    --performance-mode generalPurpose \
    --throughput-mode bursting
…

$ EFS_ID=$(aws efs describe-file-systems --creation-token malcolm-efs \
    --query 'FileSystems[0].FileSystemId' --output text)

$ echo $EFS_ID
```

* Create file system [access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html)

```bash
$ for AP in config opensearch opensearch-backup pcap runtime-logs suricata-logs zeek-logs; do \
    aws efs create-access-point \
            --file-system-id $EFS_ID \
            --client-token $(head -c 1024 /dev/urandom 2>/dev/null | tr -cd 'a-f0-9' | head -c 32) \
            --root-directory "Path=/malcolm/$AP,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=0770}" \
            --tags "Key=Name,Value=$AP"; \
done
…
```

* Get [VPC](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html) ID

```bash
$ VPC_ID=$(aws eks describe-cluster --name malcolm-cluster \
        --query "cluster.resourcesVpcConfig.vpcId" --output text)

$ echo $VPC_ID
```

* Create [Security Group](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) for EFS

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-efs-sg \
    --description "Security group for Malcolm EFS" \
    --vpc-id $VPC_ID
…

$ EFS_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=malcolm-efs-sg" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text)

$ echo $EFS_SG_ID
```

* Add NFS [inbound rule](https://docs.aws.amazon.com/quicksight/latest/user/vpc-security-groups.html) to Security Group

```bash
$ for SG in $(kubectl get nodes \
                -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}' | \
                xargs -I{} aws ec2 describe-instances \
                             --filters "Name=private-ip-address,Values={}" \
                             --query "Reservations[*].Instances[*].NetworkInterfaces[*].Groups[*].GroupId" \
                             --output text | tr '\t' '\n' | sort -u); do \
    aws ec2 authorize-security-group-ingress \
        --group-id "$EFS_SG_ID" \
        --protocol tcp \
        --port 2049 \
        --source-group "$SG"; \
done
…
```

* Get subnet IDs

```bash
$ PRIVATE_SUBNET_IDS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:aws:cloudformation:logical-id,Values=SubnetPrivate*" \
    --query 'Subnets[*].SubnetId' --output text)

$ echo $PRIVATE_SUBNET_IDS
```

* Create [EFS mount targets](https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html) for subnets

```bash
$ for subnet in $PRIVATE_SUBNET_IDS; do \
    aws efs create-mount-target \
        --file-system-id $EFS_ID \
        --subnet-id $subnet \
        --security-groups $EFS_SG_ID; \
done
…
```

* Associate necessary EFS permissions with node role (**not required for EKS Auto Mode**)

```bash
$ NODE_ROLE_NAME=$(aws iam list-roles \
                     --query "Roles[?contains(RoleName, 'eksctl-malcolm-cluster-nodegroup')].RoleName" \
                     --output text)

$ echo $NODE_ROLE_NAME

$ EFS_ARN="arn:aws:elasticfilesystem:us-east-1:$(aws sts get-caller-identity --query Account --output text):file-system/${EFS_ID}"

$ echo $EFS_ARN

$ aws iam put-role-policy \
  --role-name $NODE_ROLE_NAME \
  --policy-name AllowEFSAccess \
  --policy-document file://<(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeFileSystems",
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientWrite"
      ],
      "Resource": "$EFS_ARN"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeAvailabilityZones"
      ],
      "Resource": "*"
    }
  ]
}
EOF
)
```

* Create [Persistent Volumes](https://docs.aws.amazon.com/eks/latest/best-practices/windows-storage.html) (PV) and Persistent Volume Claims (PVC) using static provisioning
    * Ensure file system ID is exported in `$EFS_ID`

    ```bash
    $ export EFS_ID=$(aws efs describe-file-systems --creation-token malcolm-efs \
        --query 'FileSystems[0].FileSystemId' --output text)

    $ echo $EFS_ID
    ```

    * Ensure the Access Point IDs are exported in `$EFS_ACCESS_POINT_CONFIG_ID`, etc.

    ```bash
    $ for AP in config opensearch opensearch-backup pcap runtime-logs suricata-logs zeek-logs; do \
        AP_UPPER=$(echo "$AP" | tr 'a-z-' 'A-Z_'); \
        ACCESS_POINT_ID=$(aws efs describe-access-points \
                            --file-system-id $EFS_ID \
                            --query "AccessPoints[?Tags[?Key=='Name' && Value=='$AP']].AccessPointId" \
                            --output text); \

        [[ -n "$ACCESS_POINT_ID" ]] && export EFS_ACCESS_POINT_${AP_UPPER}_ID=$ACCESS_POINT_ID; \
    done

    $ env | grep EFS_ACCESS_POINT_
    …
    ```

    * Create and verify PVs and PVCs to be used by Malcolm services (see [`01-volumes-aws-efs.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-aws-efs.yml.example))

    ```bash
    $ envsubst < ./Malcolm/kubernetes/01-volumes-aws-efs.yml.example | kubectl apply -f -
    …
    ```

    * Verify PVs and PVCs have "Bound" status

    ```bash
    $ kubectl get pv -n malcolm
    NAME                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                             STORAGECLASS   VOLUMEATTRIBUTESCLASS   REASON   AGE
    config-volume              10Gi       RWX            Retain           Bound    malcolm/config-claim              efs-sc         <unset>                          11s
    opensearch-backup-volume   150Gi      RWO            Retain           Bound    malcolm/opensearch-backup-claim   efs-sc         <unset>                          10s
    opensearch-volume          150Gi      RWO            Retain           Bound    malcolm/opensearch-claim          efs-sc         <unset>                          10s
    pcap-volume                100Gi      RWX            Retain           Bound    malcolm/pcap-claim                efs-sc         <unset>                          13s
    runtime-logs-volume        10Gi       RWX            Retain           Bound    malcolm/runtime-logs-claim        efs-sc         <unset>                          11s
    suricata-volume            25Gi       RWX            Retain           Bound    malcolm/suricata-claim            efs-sc         <unset>                          12s
    zeek-volume                50Gi       RWX            Retain           Bound    malcolm/zeek-claim                efs-sc         <unset>                          13s

    $ kubectl get pvc -n malcolm
    NAME                      STATUS   VOLUME                     CAPACITY   ACCESS MODES   STORAGECLASS   VOLUMEATTRIBUTESCLASS   AGE
    config-claim              Bound    config-volume              10Gi       RWX            efs-sc         <unset>                 38s
    opensearch-backup-claim   Bound    opensearch-backup-volume   150Gi      RWO            efs-sc         <unset>                 36s
    opensearch-claim          Bound    opensearch-volume          150Gi      RWO            efs-sc         <unset>                 37s
    pcap-claim                Bound    pcap-volume                100Gi      RWX            efs-sc         <unset>                 40s
    runtime-logs-claim        Bound    runtime-logs-volume        10Gi       RWX            efs-sc         <unset>                 37s
    suricata-claim            Bound    suricata-volume            25Gi       RWX            efs-sc         <unset>                 39s
    zeek-claim                Bound    zeek-volume                50Gi       RWX            efs-sc         <unset>                 39s
    ```

* Install [AWS Load Balancer Controller](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html) via Helm

```bash
$ helm repo add eks https://aws.github.io/eks-charts
…
$ helm repo update
…
$ helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=malcolm-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-load-balancer-controller \
  --set region=us-east-1 \
  --set vpcId=$VPC_ID
…
```

* [Request a certificate](https://docs.aws.amazon.com/cli/latest/reference/acm/request-certificate.html) and get its ARN (here `malcolm.example.org` is placeholder that should be replaced with the domain name which will point to the Malcolm instance)

```bash
$ aws acm request-certificate \
  --domain-name malcolm.example.org \
  --validation-method DNS \
  --region us-east-1
…

$ CERT_ARN=$(aws acm list-certificates \
    --region us-east-1 \
    --query "CertificateSummaryList[?DomainName=='malcolm.example.org'].CertificateArn" \
    --output text)

$ echo $CERT_ARN
```

* Get the DNS [validation record](https://docs.aws.amazon.com/cli/latest/reference/acm/describe-certificate.html) from ACM

```bash
$ VALIDATION_RECORD=$(aws acm describe-certificate \
  --certificate-arn "$CERT_ARN" \
  --region us-east-1 \
  --query "Certificate.DomainValidationOptions[0].ResourceRecord" \
  --output json)

$ echo $VALIDATION_RECORD
```

* Using the dashboard or other tools provided by your domain name provider (i.e., the issuer of `malcolm.example.org` in this example), create a [DNS record of type `CNAME`](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html) with the host set to the subdomain part of `Name` (e.g., `_0954b44630d36d77d12d12ed6c03c1e4.aws` if `Name` was `_0954b44630d36d77d12d12ed6c03c1e4.aws.malcolm.example.org.`) and the value/target set to `Value` (normally including the trailing dot; however, if your domain name provider gives an error it may be attempted without the trailing dot) of `$VALIDATION_RECORD`. Wait five to ten minutes for DNS to propogate.

* Periodically check the status of the certificate until it has changed from `PENDING_VALIDATION` to `ISSUED`.

```bash
$ aws acm describe-certificate \
  --certificate-arn "$CERT_ARN" \
  --region us-east-1 \
  --query "Certificate.Status"
…
```

* Copy [`./Malcolm/config/kubernetes-container-resources.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/config/kubernetes-container-resources.yml.example) to `./Malcolm/config/kubernetes-container-resources.yml` and [adjust container resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits) in the copy.
    * This step is **required** for EKS Auto Mode and **optional** for standard EKS.

* [Start Malcolm](kubernetes.md#Running), providing the kubeconfig file as the `--file`/`-f` parameter and the additional parameters listed here. This will start the create the resources and start the pods running under the `malcolm` namespace. The `--inject-resources` argument is only required if you adjusted `kubernetes-container-resources.yml` as described above.

```bash
$ ./Malcolm/scripts/start -f "${KUBECONFIG:-$HOME/.kube/config}" \
    --inject-resources \
    --skip-persistent-volume-checks
…
```

* Create the ALB ingress for Malcolm (see [`99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example)), replacing `malcolm.example.org` with the the domain name which will point to the Malcolm instance.

    ```bash
    $ export CERT_ARN
    $ export MALCOLM_HOST=malcolm.example.org
    $ envsubst < ./Malcolm/kubernetes/99-ingress-aws-alb.yml.example | kubectl apply -f -
    …
    ```

* Allow incoming TCP connections from remote sensors using [Network Load Balancer (NLB)](https://aws.amazon.com/elasticloadbalancing/network-load-balancer/)
    * This step is **not required** for EKS Auto Mode.
    * **OPTIONAL**: This is only needed to allow forwarding from a remote [Hedgehog Linux](live-analysis.md#Hedgehog) network sensor.
    * Create and assign a security group for Logstash (5044/tcp) and Filebeat (5045/tcp) to accept logs. Replacing `0.0.0.0/0` with a more limited CIDR block in the following commands is recommended.

    ```bash
    $ aws ec2 create-security-group \
        --group-name malcolm-raw-tcp-sg \
        --description "Security group for raw TCP services" \
        --vpc-id $VPC_ID
    …

    $ TCP_SG_ID=$(aws ec2 describe-security-groups \
                    --filters Name=group-name,Values=malcolm-raw-tcp-sg \
                    --query 'SecurityGroups[0].GroupId' \
                    --output text)

    $ echo $TCP_SG_ID

    $ for PORT in 5044 5045; do \
        aws ec2 authorize-security-group-ingress \
            --group-id $TCP_SG_ID \
            --protocol tcp \
            --port $PORT \
            --cidr 0.0.0.0/0; \
    done
    …
    ```

    * Assign the new security group to the network interfaces

    ```bash
    $ for POD in logstash filebeat; do \
        POD_NAME="$(kubectl get pods -n malcolm --no-headers -o custom-columns=':metadata.name' | grep "$POD" | head -n 1)"; \
        ( [[ -n "$POD_NAME" ]] && [[ "$POD_NAME" != "None" ]] ) || continue; \
        POD_IP="$(kubectl get pod -n malcolm "$POD_NAME" -o jsonpath='{.status.podIP}')"; \
        ( [[ -n "$POD_IP" ]] && [[ "$POD_IP" != "None" ]] ) || continue; \
        NIC_ID="$(aws ec2 describe-network-interfaces --filters "Name=addresses.private-ip-address,Values=$POD_IP" --query "NetworkInterfaces[0].NetworkInterfaceId" --output text)"; \
        ( [[ -n "$NIC_ID" ]] && [[ "$NIC_ID" != "None" ]] ) || continue; \
        NIC_GROUPS="$(aws ec2 describe-network-interfaces --network-interface-ids "$NIC_ID" --query "NetworkInterfaces[0].Groups[].GroupId" --output text)"; \
        ( [[ -n "$NIC_GROUPS" ]] && [[ "$NIC_GROUPS" != "None" ]] ) || continue; \
        aws ec2 modify-network-interface-attribute \
          --network-interface-id "$NIC_ID" \
          --groups $TCP_SG_ID $NIC_GROUPS; \
    done
    …
    ```

* Get the LoadBalancer hostnames for the internet-facing services created from `./Malcolm/kubernetes/99-ingress-aws-alb.yml`. The `LOGSTASH_HOSTNAME` and `FILEBEAT_HOSTNAME` commands can be ignored if you did not configure allowing incoming TCP connections from remote sensors in the previous step.

```bash
$ HTTPS_HOSTNAME=$(kubectl get ingress malcolm-ingress-https -n malcolm -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
$ LOGSTASH_HOSTNAME=$(kubectl get service malcolm-nlb-logstash -n malcolm -o jsonpath='{.status.loadBalancer.ingress[*].hostname}')
$ FILEBEAT_HOSTNAME=$(kubectl get service malcolm-nlb-tcp-json -n malcolm -o jsonpath='{.status.loadBalancer.ingress[*].hostname}')

$ echo $HTTPS_HOSTNAME
$ echo $LOGSTASH_HOSTNAME
$ echo $FILEBEAT_HOSTNAME
```

* Using the dashboard or other tools provided by your domain name provider (i.e., the issuer of `malcolm.example.org` in this example), create a [DNS record of type `CNAME`](https://docs.aws.amazon.com/acm/latest/userguide/dns-validation.html) with the host set to your subdomain (e.g., `malcolm` if the domain is `malcolm.example.org`) and the value/target set to the value of `$HTTPS_HOSTNAME`. Wait five to ten minutes for DNS to propogate. If you also configured allowing incoming TCP connections from remote sensors above, create `CNAME` records for `$LOGSTASH_HOSTNAME` and `$FILEBEAT_HOSTNAME` as well (e.g., `logstash.malcolm.example.org` and `filebeat.malcolm.example.org`, respectively).

* Open a [web browser](quickstart.md#UserInterfaceURLs) to connect to the Malcolm cluster (e.g., `https://malcolm.example.org`)

* Monitor deployment
    * Check [pods](https://kubernetes.io/docs/tutorials/kubernetes-basics/explore/explore-intro/)

    ```bash
    $ kubectl get pods -n malcolm -w
    kubectl get pods -n malcolm -w
    NAME                                            READY   STATUS     RESTARTS   AGE
    api-deployment-5c8b9c7c5b-dtpkq                 1/1     Running    0          3m6s
    arkime-deployment-fcbb44c8f-plh8k               1/1     Running    0          3m6s
    dashboards-deployment-95467ff6f-h2zx5           1/1     Running    0          3m7s
    dashboards-helper-deployment-7686756dc4-vxw4r   1/1     Running    0          3m5s
    file-monitor-deployment-7fccbb7c98-8hxrv        1/1     Running    0          3m5s
    filebeat-deployment-57db54b549-zvfb4            1/1     Running    0          3m4s
    freq-deployment-6c7688b4c-zhdfw                 1/1     Running    0          3m2s
    htadmin-deployment-767c78b4bf-sjzmf             1/1     Running    0          3m2s
    keycloak-deployment-7ff7bb9c8c-trkc6            1/1     Running    0          3m2s
    logstash-deployment-54ffd8c85-spmh5             1/1     Running    0          3m4s
    netbox-deployment-7bdbfcbf6c-xc725              1/1     Running    0          3m3s
    nginx-proxy-deployment-864c896ff6-v8jrs         1/1     Running    0          3m1s
    opensearch-deployment-654b79f6f9-2tss2          1/1     Running    0          3m7s
    pcap-monitor-deployment-5f644fb9b-tzk8k         1/1     Running    0          3m6s
    postgres-deployment-76fb787976-pgwsr            1/1     Running    0          3m3s
    redis-cache-deployment-6f9b9d65bf-dssjt         1/1     Running    0          3m3s
    redis-deployment-7b985fb7d7-zz9jb               1/1     Running    0          3m4s
    suricata-offline-deployment-669c759f88-nt24v    1/1     Running    0          3m5s
    upload-deployment-76c6c49cb5-9zdtp              1/1     Running    0          3m7s
    zeek-offline-deployment-c56f7f46f-m62sd         1/1     Running    0          3m5s
    ```

    * [Check](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/) all resources

    ```bash
    $ kubectl get all -n malcolm
    …
    ```

    * Watch pod [logs](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/)
        * Using Malcolm's convenience script

        ```bash
        $ ./Malcolm/scripts/logs -f "${KUBECONFIG:-$HOME/.kube/config}"
        …
        ```

        * Using `kubectl`
        ```bash
        $ kubectl logs --follow=true -n malcolm --all-containers <pod>
        …
        ```

    * Get all [events](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_events/) in the namespace for more detailed information and debugging

    ```bash
    $ kubectl get events -n malcolm --sort-by='.metadata.creationTimestamp'
    …
    ```

* Stop Malcolm, providing the kubeconfig file as the `--file`/`-f` parameter. This will stop the pods and remove the resources running under the `malcolm` namespace.

```bash
$ ./Malcolm/scripts/stop -f "${KUBECONFIG:-$HOME/.kube/config}"
…
```

## <a name="AWSAMI"></a> Generating a Malcolm Amazon Machine Image (AMI)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm [AMI](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html) for either the x86-64 or arm64 CPU architecture. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

The files referenced in this section can be found in [scripts/third-party-environments/aws/ami]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/third-party-environments/aws/ami).

* Copy `packer_vars.json.example` to `packer_vars.json`

```bash
$ cp ./packer_vars.json.example ./packer_vars.json
```

* Edit `packer_vars.json`
    * Set `vpc_region`, `instance_arch`, and other variables as needed
* Validate the `packer` configuration

```bash
$ packer validate packer_build.json
The configuration is valid.
```

* Launch `packer` to build the AMI, providing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as environment variables:

```bash
$ AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY \
    AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET_KEY \
    packer build -var-file=packer_vars.json packer_build.json

amazon-ebs: output will be in this color.

==> amazon-ebs: Prevalidating any provided VPC information
==> amazon-ebs: Prevalidating AMI Name: malcolm-v{{ site.malcolm.version }}-x86_64-2024-10-10T15-41-32Z
    amazon-ebs: Found Image ID: ami-xxxxxxxxxxxxxxxxx

...

==> amazon-ebs: Waiting for AMI to become ready...
==> amazon-ebs: Skipping Enable AMI deprecation...
==> amazon-ebs: Adding tags to AMI (ami-xxxxxxxxxxxxxxxxx)...
==> amazon-ebs: Tagging snapshot: snap-xxxxxxxxxxxxxxxxx
==> amazon-ebs: Creating AMI tags
    amazon-ebs: Adding tag: "Malcolm": "idaholab/Malcolm/v{{ site.malcolm.version }}"
    amazon-ebs: Adding tag: "source_ami_name": "al2023-ami-ecs-hvm-2023.0.20241003-kernel-6.1-x86_64"
==> amazon-ebs: Creating snapshot tags
==> amazon-ebs: Terminating the source AWS instance...
==> amazon-ebs: Cleaning up any extra volumes...
==> amazon-ebs: No volumes to clean up, skipping
==> amazon-ebs: Deleting temporary keypair...
Build 'amazon-ebs' finished after 19 minutes 57 seconds.

==> Wait completed after 19 minutes 57 seconds

==> Builds finished. The artifacts of successful builds are:
--> amazon-ebs: AMIs were created:
us-east-1: ami-xxxxxxxxxxxxxxxxx
```

* Use [`aws`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html) (or the Amazon EC2 console) to verify that the new AMI exists and note the ID of the image to launch if you wish to continue on to the next section.

```bash
$ aws ec2 describe-images \
    --owners self \
    --filters "Name=root-device-type,Values=ebs" \
    --filters "Name=name,Values=malcolm-*" \
    --query "Images[*].[Name,ImageId,CreationDate]" \
    --output text | sort

malcolm-v25.03.1-arm64-2025-03-31T18-28-00Z     ami-xxxxxxxxxxxxxxxxx   2025-03-31T18:33:12.000Z
malcolm-v25.03.1-x86_64-2025-03-31T18-13-34Z    ami-xxxxxxxxxxxxxxxxx   2025-03-31T18:19:17.000Z
```

### <a name="AWSAMILaunch"></a> Launching an EC2 instance from the Malcolm AMI

* Create a [key pair for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html)

```bash
$ aws ec2 create-key-pair \
    --key-name malcolm-key \
    --query "KeyMaterial" \
    --output text > ./malcolm-key.pem

$ chmod 600 ./malcolm-key.pem
```

* Create a [security group for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-sg \
    --description "Malcolm SG"
…
```

* Set inbound [security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
    - These rules will allow SSH and HTTPS access from the address(es) specified
    - Replace `#.#.#.#` with the public IP address(es) (i.e., addresses which will be allowed to connect to the Malcolm instance via SSH and HTTPS) in the following commands

```bash
$ PUBLIC_IP=#.#.#.#

$ for PORT in 22 443; do \
    aws ec2 authorize-security-group-ingress \
        --group-name malcolm-sg \
        --protocol tcp \
        --port $PORT \
        --cidr $PUBLIC_IP/32; \
done
…
```

* Launch selected AMI
    - Replace `INSTANCE_TYPE` with the desired instance type in the following command
        + See [EC2 Instance Types](#AWSInstanceSizing) for suggestions
    - Replace `AMI_ID` with the AMI ID from above in the following command
    - The size of the storage volume will vary depending on the amount of data users plan to process and retain in Malcolm. The example here uses 100 GiB; users should adjust as needed for their specific use case.

```bash
$ aws ec2 run-instances \
    --image-id AMI_ID \
    --instance-type INSTANCE_TYPE \
    --key-name malcolm-key \
    --security-group-ids malcolm-sg \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":100,\"VolumeType\":\"gp3\"}}]" \
    --count 1 \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=Malcolm}]"
…
```

* Get [instance details](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html) and check its status

```bash
$ aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=Malcolm" \
    --query "Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name}" \
    --output table
…
```

* Connect via [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or via SSH using the key pair created above.

```bash
$ INSTANCE_IP=$(aws ec2 describe-instances \
                  --filters "Name=tag:Name,Values=Malcolm" \
                  --query "Reservations[].Instances[].PublicIpAddress" \
                  --output text)

$ ssh -o IdentitiesOnly=yes -i ./malcolm-key.pem ec2-user@$INSTANCE_IP
```

* Upon connection, Malcolm will automatically prompt the user to complete [configuration](malcolm-config.md#ConfigAndTuning) and set up [authentication](authsetup.md#AuthSetup).
    - Users should answer the remaining [configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) as they apply to their use case.
    - [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the authentication setup prompts.

* Start Malcolm
    - Running `~/Malcolm/scripts/start` will [start Malcolm](running.md#Starting).
    - Malcolm takes a few minutes to start. During this time users may see text scroll past from the containers' logs that look like error messages. This is normal while Malcolm's services synchronize among themselves.
    - Once Malcolm is running, the start script will output **Started Malcolm** and return to the command prompt.

* Check Malcolm's status
    - Running `./scripts/status` in the Malcolm installation directory will display the status of Malcolm's services.

* Connect to Malcolm's [web interface](quickstart.md#UserInterfaceURLs)
    - Navigate a web browser to the IP address of the instance using HTTPS
    - Log in with the credentials specified when setting up authentication
    - See the Malcolm [Learning Tree](https://github.com/cisagov/Malcolm/wiki/Learning) and [documentation](README.md) for next steps.

### <a name="AWSAMIMFA"></a> Using MFA

Users with [AWS MFA requirements](https://docs.aws.amazon.com/console/iam/self-mfa) may receive an `UnauthorizedOperation` error when performing the steps outlined above. If this is the case, the following workaround may allow the build to execute (thanks to [this GitHub comment](https://github.com/hashicorp/packer-plugin-amazon/issues/441#issuecomment-1880073476)):

1. Remove the `access_key` and `secret_key` lines from the `builders` section of `packer_build.json` (right below `"type": "amazon-ebs"`)
1. Run `aws ec2 describe-instances --profile=xxxxxxxx` (replacing `xxxxxxxx` with the credential profile name) to cause `aws` to authenticate (prompting for the MFA code) and cache the credentials
1. At the bash command line, run: `eval "$(aws configure export-credentials --profile xxxxxxxx --format env)"` to load the current AWS credentials into environment variables in the current session
1. Run the `packer build` command as described above

## <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, Amazon Elastic Kubernetes Service (EKS), and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation.
