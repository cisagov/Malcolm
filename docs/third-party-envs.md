# <a name="ThirdPartyEnv"></a>Deploying Malcolm in Other Third-Party Environments

* [Deploying Malcolm in Other Third-Party Environments](#ThirdPartyEnv)
    - [Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)](#AWSAMI)
        + [Prerequisites](#AWSAMIPrerequisites)
        + [Procedure](#AWSAMIProcedure)
        + [Attribution](#AWSAttribution)

## <a name="AWSAMI"></a>Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm AMI. This section assumes you have good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

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
    * set `aws_access_key`, `aws_secret_key`, `vpc_region`, and other variables as needed
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
    ==> amazon-ebs: Prevalidating AMI Name: malcolm-amzn2_v1-2023-05-30T21-12-22Z
        amazon-ebs: Found Image ID: ami-0bef6cc322bfff646

    ...

    ==> amazon-ebs: Waiting for AMI to become ready...
    ==> amazon-ebs: Skipping Enable AMI deprecation...
    ==> amazon-ebs: Terminating the source AWS instance...
    ==> amazon-ebs: Cleaning up any extra volumes...
    ==> amazon-ebs: No volumes to clean up, skipping
    ==> amazon-ebs: Deleting temporary keypair...
    Build 'amazon-ebs' finished after 3 minutes 47 seconds.

    ==> Wait completed after 3 minutes 47 seconds

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
                "CreationDate": "2023-05-31T17:07:42.000Z",
                "ImageId": "ami-xxxxxxxxxxxxxxxxx",
                "ImageLocation": "xxxxxxxxxxxx/malcolm-v23.05.1-2023-05-31T16-58-00Z",
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
                "Name": "malcolm-v23.05.1-2023-05-31T16-58-00Z",
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SriovNetSupport": "simple",
                "Tags": [
                    {
                        "Key": "Malcolm",
                        "Value": "idaholab/Malcolm/v23.05.1"
                    },
                    {
                        "Key": "source_ami_name",
                        "Value": "amzn2-ami-kernel-5.10-hvm-2.0.20230515.0-x86_64-gp2"
                    }
                ],
                "VirtualizationType": "hvm"
            }
        ]
    }
    ```
1. Launch an instance from the new AMI
    * Both `c4.4xlarge` and `t3a.2xlarge` seem to be good instance types for Malcolm
1. SSH into the instance
1. Run `~/Malcolm/scripts/configure` to configure Malcolm
1. Run `~/Malcolm/scripts/auth_setup` to set up authentication for Malcolm
1. Run `~/Malcolm/scripts/start` to start Malcolm

### <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
