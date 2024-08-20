# <a name="ThirdPartyEnv"></a>Deploying Malcolm in Other Third-Party Environments

* [Deploying Malcolm in Other Third-Party Environments](#ThirdPartyEnv)
    - [Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)](#AWSAMI)
        + [Prerequisites](#AWSAMIPrerequisites)
        + [Procedure](#AWSAMIProcedure)
        + [Attribution](#AWSAttribution)

## <a name="AWSAMI"></a>Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm AMI for either the x86-64 or arm64 CPU architecture. This section assumes you have good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSAMIPrerequisites"></a> Prerequisites

* [packer](https://www.packer.io/)
    - the packer command-line tool ([download](https://developer.hashicorp.com/packer/downloads))
* [aws cli](https://aws.amazon.com/cli/)
    - the AWS Command Line Interface with functioning access to your AWS infrastructure
* AWS access key ID and secret access key
    - [AWS security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html)
* ensure the AWS account you are using for packer has minimal required permissions
    - [Amazon AMI builder](https://developer.hashicorp.com/packer/plugins/builders/amazon)

### <a name="AWSAMIProcedure"></a> Procedure

The files referenced in this section can be found in [scripts/third-party-environments/aws/ami]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/third-party-environments/aws/ami).

1. Copy `packer_vars.json.example` to `packer_vars.json`
    ```bash
    $ cp ./packer_vars.json.example ./packer_vars.json
    ```
1. Edit `packer_vars.json` 
    * set `aws_access_key`, `aws_secret_key`, `vpc_region`, `instance_arch`, and other variables as needed
1. Validate the packer configuration
    ```bash
    $ packer validate packer_build.json
    The configuration is valid.
    ```
1. Launch packer to build the AMI
    ```bash
    $ packer build -var-file=packer_vars.json packer_build.json

    amazon-ebs: output will be in this color.

    ==> amazon-ebs: Prevalidating any provided VPC information
    ==> amazon-ebs: Prevalidating AMI Name: malcolm-v24.08.0-arm64-2024-05-30T13-57-31Z
        amazon-ebs: Found Image ID: ami-xxxxxxxxxxxxxxxxx

    ...

    ==> amazon-ebs: Waiting for AMI to become ready...
    ==> amazon-ebs: Skipping Enable AMI deprecation...
    ==> amazon-ebs: Adding tags to AMI (ami-xxxxxxxxxxxxxxxxx)...
    ==> amazon-ebs: Tagging snapshot: snap-xxxxxxxxxxxxxxxxx
    ==> amazon-ebs: Creating AMI tags
        amazon-ebs: Adding tag: "Malcolm": "idaholab/Malcolm/v24.08.0"
        amazon-ebs: Adding tag: "source_ami_name": "amzn2-ami-kernel-5.10-hvm-2.0.20240521.0-arm64-gp2"
    ==> amazon-ebs: Creating snapshot tags
    ==> amazon-ebs: Terminating the source AWS instance...
    ==> amazon-ebs: Cleaning up any extra volumes...
    ==> amazon-ebs: No volumes to clean up, skipping
    ==> amazon-ebs: Deleting temporary keypair...
    Build 'amazon-ebs' finished after 23 minutes 58 seconds.

    ==> Wait completed after 23 minutes 58 seconds

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
                "Architecture": "arm64",
                "CreationDate": "2024-05-30T14:02:21.000Z",
                "ImageId": "ami-xxxxxxxxxxxxxxxxx",
                "ImageLocation": "xxxxxxxxxxxx/malcolm-v24.08.0-arm64-2024-05-30T13-57-31Z",
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
                            "VolumeSize": 20,
                            "VolumeType": "gp2",
                            "Encrypted": false
                        }
                    }
                ],
                "EnaSupport": true,
                "Hypervisor": "xen",
                "Name": "malcolm-v24.08.0-arm64-2024-05-30T13-57-31Z",
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SriovNetSupport": "simple",
                "Tags": [
                    {
                        "Key": "Malcolm",
                        "Value": "idaholab/Malcolm/v24.08.0"
                    },
                    {
                        "Key": "source_ami_name",
                        "Value": "amzn2-ami-kernel-5.10-hvm-2.0.20240521.0-arm64-gp2"
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

### <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
