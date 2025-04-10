# <a name="ThirdPartyEnv"></a>Deploying Malcolm in Other Third-Party Environments

* [Deploying Malcolm in Other Third-Party Environments](#ThirdPartyEnv)
    - [Installing Malcolm in an EC2 instance on Amazon Web Services (AWS)](#AWSEC2)
        + [Prerequisites](#AWSEC2Prerequisites)
        + [Procedure](#AWSEC2Procedure)
            - [Instance creation](#AWSEC2Instance)
            - [Malcolm setup](#AWSEC2Install)
            - [Running Malcolm](#AWSEC2Run)
    - [Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)](#AWSAMI)
        + [Prerequisites](#AWSAMIPrerequisites)
        + [Procedure](#AWSAMIProcedure)
            * [Using MFA](#AWSAMIMFA)
    - [Attribution](#AWSAttribution)

## <a name="AWSEC2"></a>Installing Malcolm in an EC2 instance on Amazon Web Services (AWS)

This section outlines the process of using the [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/) to instantiate an [EC2](https://aws.amazon.com/ec2/) instance running Malcolm. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSEC2Prerequisites"></a> Prerequisites

* [aws cli](https://aws.amazon.com/cli/)
    - the AWS Command Line Interface with functioning access to AWS infrastructure

### <a name="AWSEC2Procedure"></a> Procedure

#### <a name="AWSEC2Instance"></a> Instance creation

These steps are to be run on a Linux, Windows, or macOS system in a command line environment with the [AWS Command Line Interface (AWS CLI)](https://aws.amazon.com/cli/) installed. Users should adjust these steps to their own use cases in terms of naming resources, setting security policies, etc.

* Create a [key pair for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html)

```bash
$ aws ec2 create-key-pair \
    --key-name malcolm-key \
    --query "KeyMaterial" \
    --output text > malcolm-key.pem
```

* Create a [security group for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-sg \
    --description "Malcolm SG"
```

* Set inbound [security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
    - These rules will allow SSH and HTTPS access from the address(es) specified
    - Replace `YOUR_PUBLIC_IP` with the public IP address(es) (i.e., addresses which will be allowed to connect to the Malcolm instance via SSH and HTTPS) in the following commands

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-name malcolm-sg \
    --protocol tcp \
    --port 22 \
    --cidr YOUR_PUBLIC_IP/32
$ aws ec2 authorize-security-group-ingress \
    --group-name malcolm-sg \
    --protocol tcp \
    --port 443 \
    --cidr YOUR_PUBLIC_IP/32
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
    --output text
```

* Launch selected AMI
    - Malcolm is a resource-intensive tool: instance types should meet Malcolm's [minimum system requirements](system-requirements.md#SystemRequirements). Some instance types meeting recommended minimum requirements:
        + amd64
            * [c4.4xlarge](https://aws.amazon.com/ec2/instance-types/#Compute_Optimized), [t2.2xlarge, or t3a.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose)
        + arm64
            * [m6gd.2xlarge, m6g.2xlarge, m7g.2xlarge, and t4g.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose)
    - Replace `INSTANCE_TYPE` with the desired instance type in the following command
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
```

* Get [instance details](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html) and check its status

```bash
$ aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=Malcolm" \
    --query "Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name}"
```

#### <a name="AWSEC2Install"></a> Malcolm setup

The next steps are to be run as the `ubuntu` user inside the EC2 instance, either connected via [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or via SSH using the key pair created in step 1.

* Install `curl` and `unzip`

```bash
$ sudo apt-get -y update
…

$ sudo apt-get -y install curl unzip
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
    - After the first question, the installer will then switch to a dialog-based wizard.
    - Use the following resources to answer the installation and configuration questions:
        + [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        + [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)

```bash
$ ./install.py
1: docker
2: podman
Select container runtime engine (docker): 1
…
```

* `install.py`: Docker installation and system configuration
    - The [installer script](malcolm-config.md#ConfigAndTuning) will install and configure Docker and Docker Compose, and make necessary changes to system configuration.

```bash
"docker info" failed, attempt to install Docker? (Y / n): y

Attempt to install Docker using official repositories? (Y / n): y

Apply recommended system tweaks automatically without asking for confirmation? y
…
```

* `install.py`: Malcolm configuration
    - Users should answer the remaining (malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) as they apply to their use case.

* Pull Malcolm container images
    - Answer **Yes** when prompted to **Pull Malcolm images?**
    - Pulling the container images may take several minutes.

* Reboot the instance
    - This allows the changes to system configuration to take effect
    - After a few minutes, reconnect via Session Manager or SSH

```bash
$ sudo reboot
…
```

* Set up authentication
    - [Configure authentication](authsetup.md#AuthSetup) using `./scripts/auth_setup` in the Malcolm installation directory.
    - [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the remaining prompts.

```bash
$ cd ~/malcolm

$ ./scripts/auth_setup

all        Configure all authentication-related settings
…
```

#### <a name="AWSEC2Run"></a> Running Malcolm

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
    - Navigate a web browser to the IP address of the instance (from step 6) using HTTPS
    - Log in with the credentials specified when setting up authentication
    - See the Malcolm [Learning Tree](https://github.com/cisagov/Malcolm/wiki/Learning) and [documentation](README.md) for next steps.

## <a name="AWSAMI"></a>Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm AMI for either the x86-64 or arm64 CPU architecture. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSAMIPrerequisites"></a> Prerequisites

* [packer](https://www.packer.io/)
    - the packer command-line tool ([download](https://developer.hashicorp.com/packer/downloads))
* [aws cli](https://aws.amazon.com/cli/)
    - the AWS Command Line Interface with functioning access to AWS infrastructure
* AWS access key ID and secret access key
    - [AWS security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html)
* ensure the AWS account used for packer has minimal required permissions
    - [Amazon AMI builder](https://developer.hashicorp.com/packer/plugins/builders/amazon)

### <a name="AWSAMIProcedure"></a> Procedure

The files referenced in this section can be found in [scripts/third-party-environments/aws/ami]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/third-party-environments/aws/ami).

1. Copy `packer_vars.json.example` to `packer_vars.json`
    ```bash
    $ cp ./packer_vars.json.example ./packer_vars.json
    ```
1. Edit `packer_vars.json` 
    * set `vpc_region`, `instance_arch`, and other variables as needed
1. Validate the packer configuration
    ```bash
    $ packer validate packer_build.json
    The configuration is valid.
    ```
1. Launch packer to build the AMI, providing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as environment variables:
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
1. Use `aws` (or the [Amazon EC2 console](https://us-east-1.console.aws.amazon.com/ec2/home)) to verify that the new AMI exists
    ```bash
    $ aws ec2 describe-images --owners self --filters "Name=root-device-type,Values=ebs" --filters "Name=name,Values=malcolm-*"
    ```
    ```json
    {
        "Images": [
            {
                "Architecture": "x86_64",
                "CreationDate": "2024-05-30T14:02:21.000Z",
                "ImageId": "ami-xxxxxxxxxxxxxxxxx",
                "ImageLocation": "xxxxxxxxxxxx/malcolm-v{{ site.malcolm.version }}-arm64-2024-05-30T13-57-31Z",
                "ImageType": "machine",
                "Public": false,
                "OwnerId": "xxxxxxxxxxxx",
                "PlatformDetails": "Linux/UNIX",
                "UsageOperation": "RunInstances",
                "State": "available",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "DeleteOnTermination": true,
                            "SnapshotId": "snap-xxxxxxxxxxxxxxxxx",
                            "VolumeSize": 30,
                            "VolumeType": "gp2",
                            "Encrypted": false
                        }
                    }
                ],
                "EnaSupport": true,
                "Hypervisor": "xen",
                "Name": "malcolm-v{{ site.malcolm.version }}-arm64-2024-05-30T13-57-31Z",
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SriovNetSupport": "simple",
                "Tags": [
                    {
                        "Key": "Malcolm",
                        "Value": "idaholab/Malcolm/v{{ site.malcolm.version }}"
                    },
                    {
                        "Key": "source_ami_name",
                        "Value": "al2023-ami-ecs-hvm-2023.0.20241003-kernel-6.1-x86_64"
                    }
                ],
                "VirtualizationType": "hvm",
                "BootMode": "uefi",
                "SourceInstanceId": "i-xxxxxxxxxxxxxxxxx",
                "DeregistrationProtection": "disabled"
            }
        ]
    }
    ```
1. Launch an instance from the new AMI
    * for x86-64 instances `c4.4xlarge`, `t2.2xlarge`, and `t3a.2xlarge` seem to be good instance types for Malcolm
    * for arm64 instances, `m6gd.2xlarge`, `m6g.2xlarge`, `m7g.2xlarge`, and `t4g.2xlarge` seem to be good instance types for Malcolm
    * see [recommended system requirements](system-requirements.md#SystemRequirements) for Malcolm
1. SSH into the instance
1. Run `~/Malcolm/scripts/configure` to configure Malcolm
1. Run `~/Malcolm/scripts/auth_setup` to set up authentication for Malcolm
1. Run `~/Malcolm/scripts/start` to start Malcolm

### <a name="AWSAMIMFA"></a> Using MFA

Users with [AWS MFA requirements](https://docs.aws.amazon.com/console/iam/self-mfa) may receive an `UnauthorizedOperation` error when performing the steps outlined above. If this is the case, the following workaround may allow the build to execute (thanks to [this GitHub comment](https://github.com/hashicorp/packer-plugin-amazon/issues/441#issuecomment-1880073476)):

1. Remove the `access_key` and `secret_key` lines from the `builders` section of `packer_build.json` (right below `"type": "amazon-ebs"`)
1. Run `aws ec2 describe-instances --profile=xxxxxxxx` (replacing `xxxxxxxx` with the credential profile name) to cause `aws` to authenticate (prompting for the MFA code) and cache the credentials
1. At the bash command line, run: `eval "$(aws configure export-credentials --profile xxxxxxxx --format env)"` to load the current AWS credentials into environment variables in the current session
1. Run the `packer build` command as described in the previous section

## <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
