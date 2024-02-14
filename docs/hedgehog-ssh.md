# <a name="HedgehogConfigSSH"></a>Appendix C - Configuring SSH access

SSH access to the sensor's non-privileged sensor account is only available using secure key-based authentication which can be enabled by adding a public SSH key to the **/home/sensor/.ssh/authorized_keys** file as illustrated below:

```
sensor@sensor:~$ mkdir -p ~/.ssh

sensor@sensor:~$ ssh analyst@172.16.10.48 "cat ~/.ssh/id_rsa.pub" >> ~/.ssh/authorized_keys
The authenticity of host '172.16.10.48 (172.16.10.48)' can't be established.
ECDSA key fingerprint is SHA256:...
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.16.10.48' (ECDSA) to the list of known hosts.
analyst@172.16.10.48's password:

sensor@sensor:~$ cat ~/.ssh/authorized_keys
ssh-rsa AAA...kff analyst@SOC
```

SSH access should only be configured when necessary.