# <a name="HedgehogUpgradePlan"></a>Appendix E - Upgrades

At this time there is not an "official" upgrade procedure to get from one release of Hedgehog Linux to the next. Upgrading the underlying operating system packages is generally straightforward, but not all of the Hedgehog Linux components are packaged into .deb archives yet as they should be, so for now it's a manual (and kind of nasty) process to Frankenstein an upgrade into existance. The author of this project intends to remedy this at some future point when time and resources allow.

If possible, it would save you **a lot** of trouble to just [re-ISO](hedgehog-installation.md#HedgehogInstallation) your Hedgehog installation and start fresh, backing up the files (in `/opt/sensor/sensor_ctl`) first and reconfiguring or restoring them as needed afterwards. 

However, if reinstalling the system is not an option, here is the basic process for doing a manual upgrade of Hedgehog Linux. It should be understood that this process is very likely to break your system, and there is **no** guarantee of any kind that any of this will work, or that these instructions are even complete or any support whatsoever regarding them. Really, it will be **much** easier if you re-ISO your installation. But for the brave among you, here you go. ⛔🆘😭💀

## Prerequisites

* A good understanding of the Linux command line
* An existing installation of Hedgehog Linux **with internet access**
* A copy of the Hedgehog Linux [ISO](hedgehog-iso-build.md#HedgehogISOBuild) for the version approximating the one you're upgrading to (i.e., the latest version), **and**
    - Either a separate VM with that ISO installed **OR**
    - A separate Linux workstation where you can manually mount that ISO to pull stuff off of it

## Upgrade

1. Obtain a root shell
    - `su -`
    
2. Temporarily set the umask value to Debian default instead of the more restrictive Hedgehog Linux default. This will allow updates to be applied with the right permissions.
    - `umask 0022` 

3. Create backups of some files
    - `cp /etc/apt/sources.list /etc/apt/sources.list.bak`

4. Set up alternate package sources, if needed
    - In an offline/airgapped scenario, you could use [apt-mirror](https://apt-mirror.github.io) to mirror Debian repos and [bandersnatch](https://github.com/pypa/bandersnatch/) to mirror PyPI sources, or [combine them](https://github.com/mmguero/espejo) with Docker. If you were to do this, you'd probably want to make the following changes (and **revert them after the upgrade**):        
        + create `/etc/apt/apt.conf.d/80ssl-exceptions` to ignore self-signed certificate warnings from using your apt-mirror
```
Acquire::https {
  Verify-Peer "false";
  Verify-Host "false";
}
```
        
        + modify `/etc/apt/source.list` to point to your apt-mirror:

```
deb https://XXXXXX:443/debian buster main contrib non-free
deb https://XXXXXX:443/debian-security buster/updates main contrib non-free
deb https://XXXXXX:443/debian buster-updates main contrib non-free
deb https://XXXXXX:443/debian buster-backports main contrib non-free
```

5. Update underlying system packages with `apt-get`
    - `apt-get update && apt-get dist-upgrade`

6. If there were [new system deb packages added]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/sensor-iso/config/package-lists) to this release of Hedgehog Linux (you might have to [manually compare]({{ site.github.repository_url }}/commits/main/sensor-iso/config/package-lists) on GitHub), install them. If you're not sure, of course, you could just install everything, like this (although you may have to tweak some version numbers or something if the base distribution of your Hedgehog branch is different than `main`; in this example I'm not jumping between Debian releases, just upgrading within a release):
```
$ for LIST in apps desktopmanager net system; do curl -L -J -O {{ site.github.repository_url }}/main/sensor-iso/config/package-lists/$LIST.list.chroot; done
...
$ apt-get install $(cat *.list.chroot)
```

7. Update underlying python packages with `python3 -m pip`
    * `apt-get install -y build-essential git-core pkg-config python3-dev`
    * `python3 -m pip list --outdated --format=freeze | grep -v '^\-e' | cut -d = -f 1 | xargs -r -n1 python3 -m pip install -U`
        - if this fails for some reason, you may need to reinstall pip first with `python3 -m pip install --force -U pip`
        - some *very* old builds of Hedgehog Linux had separate Python 3.5 and 3.7 installations: in this case, you'd need to do this for both `python3 -m pip` and `python3.7 -m pip` (or whatever `python3.x` you have)
    * If there were [new python packages](https://raw.githubusercontent.com/{{ site.github.repository_nwo }}/master/sensor-iso/config/hooks/normal/0169-pip-installs.hook.chroot) added to this release of Hedgehog Linux (you might have to [manually compare]({{ site.github.repository_url }}/blame/main/sensor-iso/config/hooks/normal/0169-pip-installs.hook.chroot) on GitHub), install them. If you are using a PyPI mirror, replace `XXXXXX` here with your mirror's IP. The `colorama` package is used here as an example, your package list might vary.
        - `python3 -m pip install --no-compile --no-cache-dir --force-reinstall --upgrade --index-url=https://XXXXXX:443/pypi/simple --trusted-host=XXXXXX:443 colorama`

8. Okay, **now** things start to get a little bit ugly. You're going to need access to the ISO of the release of Hedgehog Linux you're upgrading to, as we're going to grab some packages off of it. On another Linux system, [build it](hedgehog-iso-build.md#HedgehogISOBuild).

9. Use a disk image mounter to mount the ISO, **or** if you want to just install the ISO in a VM and grab the files we need off of it, that's fine too. But I'll go through the example as if I've mounted the ISO.

10. Navigate to the `/live/` directory, and mount the `filesystem.squashfs` file
    - `sudo mount filesystem.squashfs /media/squash -t squashfs -o loop`
    - **OR**
    - `squashfuse filesystem.squashfs /home/user/media/squash`

11. Very recent builds of Hedgehog Linux keep some build artifacts in `/opt/hedgehog_install_artifacts/`. You're going to want to grab those files and throw them in a temporary directory on the system you're upgrading, via SSH or whatever means you devise.
```
root@hedgehog:/tmp# scp -r user@otherbox:/media/squash/opt/hedgehog_install_artifacts/ ./
user@otherbox's password: 
filebeat-tweaked-7.6.2-amd64.deb                                                100%   13MB  65.9MB/s   00:00    
arkime_2.2.3-1_amd64.deb                                                        100%  113MB  32.2MB/s   00:03    
netsniff-ng_0.6.6-1_amd64.deb                                                   100%  330KB  52.1MB/s   00:00    
zeek_3.0.20-1_amd64.deb                                                         100%   26MB  63.1MB/s   00:00
```

12. Blow away the old `zeek` package, we're going to start clean with that one particularly. The others should be fine to upgrade in place.
```
root@hedgehog:/opt# apt-get --purge remove zeek
Reading package lists... Done
Building dependency tree       
Reading state information... Done
The following packages will be REMOVED:
  zeek*
0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
After this operation, 160 MB disk space will be freed.
Do you want to continue? [Y/n] y
(Reading database ... 118490 files and directories currently installed.)
Removing zeek (3.0.20-1) ...
dpkg: warning: while removing zeek, directory '/opt/zeek/spool' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/share/zeek/site' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/lib' not empty so not removed
dpkg: warning: while removing zeek, directory '/opt/zeek/bin' not empty so not removed
root@hedgehog:/opt# rm -rf /opt/zeek*
```

13. Install the new .deb files. You're going to have some warnings, but that's okay.
```
root@hedgehog:/tmp# dpkg -i hedgehog_install_artifacts/*.deb
(Reading database ... 118149 files and directories currently installed.)
Preparing to unpack .../filebeat-tweaked-7.6.2-amd64.deb ...
Unpacking filebeat (7.6.2) over (6.8.4) ...
dpkg: warning: unable to delete old directory '/usr/share/filebeat/kibana/6/dashboard': Directory not empty
dpkg: warning: unable to delete old directory '/usr/share/filebeat/kibana/6': Directory not empty
Preparing to unpack .../arkime_2.2.3-1_amd64.deb ...
Unpacking arkime (2.2.3-1) over (2.0.1-1) ...
Preparing to unpack .../netsniff-ng_0.6.6-1_amd64.deb ...
Unpacking netsniff-ng (0.6.6-1) over (0.6.6-1) ...
Preparing to unpack .../zeek_3.0.20-1_amd64.deb ...
Unpacking zeek (3.0.20-1) over (3.0.0-1) ...
Setting up filebeat (7.6.2) ...
Installing new version of [...]
[...]
Setting up arkime (2.2.3-1) ...
READ /opt/arkime/README.txt and RUN /opt/arkime/bin/Configure
Setting up netsniff-ng (0.6.6-1) ...
Setting up zeek (3.0.20-1) ...
Processing triggers for systemd (232-25+deb9u12) ...
Processing triggers for man-db (2.7.6.1-2) ...
```

14. Fix anything that might need fixing as far as the deb package requirements go
    - `apt-get -f install`

15. We just installed a Zeek .deb, but the third-part plugins packages and local config weren't part of that package. So we're going to `rsync` those from the other box where we have the ISO and `filesystem.squashfs` mounted as well:
```
root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/zeek/ /opt/zeek 
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /opt/zeek/share/zeek/site/
total 52
lrwxrwxrwx  1 root root    13 May  6 21:52 bzar -> packages/bzar
lrwxrwxrwx  1 root root    22 May  6 21:50 cve-2020-0601 -> packages/cve-2020-0601
-rw-r--r--  1 root root  2031 Apr 30 16:02 extractor.zeek
-rw-r--r--  1 root root 39134 May  1 14:20 extractor_params.zeek
lrwxrwxrwx  1 root root    14 May  6 21:52 hassh -> packages/hassh
lrwxrwxrwx  1 root root    12 May  6 21:52 ja3 -> packages/ja3
-rw-rw-r--  1 root root  2005 May  6 21:54 local.zeek
drwxr-xr-x 13 root root  4096 May  6 21:52 packages
lrwxrwxrwx  1 root root    27 May  6 21:52 zeek-EternalSafety -> packages/zeek-EternalSafety
lrwxrwxrwx  1 root root    26 May  6 21:52 zeek-community-id -> packages/zeek-community-id
lrwxrwxrwx  1 root root    27 May  6 21:51 zeek-plugin-bacnet -> packages/zeek-plugin-bacnet
lrwxrwxrwx  1 root root    25 May  6 21:51 zeek-plugin-enip -> packages/zeek-plugin-enip
lrwxrwxrwx  1 root root    29 May  6 21:51 zeek-plugin-profinet -> packages/zeek-plugin-profinet
lrwxrwxrwx  1 root root    27 May  6 21:52 zeek-plugin-s7comm -> packages/zeek-plugin-s7comm
lrwxrwxrwx  1 root root    24 May  6 21:52 zeek-plugin-tds -> packages/zeek-plugin-tds
```

16. The `zeekctl` component of zeek doesn't like being run by an unprivileged user unless the whole directory is owned by that user. As Hedgehog Linux runs everything it can as an unprivileged user, we're going to reset zeek to a "clean" state after each reboot. Zeek's config files will get regenerated when Zeek itself is started. So, now make a complete backup of `/opt/zeek` as it's going to have its ownership changed during runtime:
```
root@hedgehog:/tmp# rsync -a /opt/zeek/ /opt/zeek.orig

root@hedgehog:/tmp# chown -R sensor:sensor /opt/zeek/*

root@hedgehog:/tmp# chown -R root:root /opt/zeek.orig/*

root@hedgehog:/tmp# ls -l /opt/ | grep zeek
drwxr-xr-x  8 root   root    4096 May  8 15:48 zeek
drwxr-xr-x  8 root   root    4096 May  8 15:48 zeek.orig
```

17. Grab other new scripts and stuff from our mount of the ISO using `rsync`:
```
root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/usr/local/bin/ /usr/local/bin
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /usr/local/bin/ | tail
lrwxrwxrwx 1 root root        18 May  8 14:34 zeek -> /opt/zeek/bin/zeek
-rwxr-xr-x 1 root staff    10349 Oct 29  2019 zeek_carve_logger.py
-rwxr-xr-x 1 root staff    10467 Oct 29  2019 zeek_carve_scanner.py
-rw-r--r-- 1 root staff    25756 Oct 29  2019 zeek_carve_utils.py
-rwxr-xr-x 1 root staff     8787 Oct 29  2019 zeek_carve_watcher.py
-rwxr-xr-x 1 root staff     4883 May  4 17:39 zeek_install_plugins.sh

root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/yara-rules/ /opt/yara-rules
user@otherbox's password: 

root@hedgehog:/tmp# rsync -a user@otherbox:/media/squash/opt/capa-rules/ /opt/capa-rules
user@otherbox's password: 

root@hedgehog:/tmp# ls -l /opt/ | grep '\-rules'
drwxr-xr-x  8 root   root    4096 May  8 15:48 capa-rules
drwxr-xr-x  8 root   root  24576  May  8 15:48 yara-rules

root@hedgehog:/tmp# for BEAT in filebeat; do rsync -a user@otherbox:/media/squash/usr/share/$BEAT/kibana/ /usr/share/$BEAT/kibana; done
user@otherbox's password: 
user@otherbox's password: 

root@hedgehog:/tmp# rsync -avP --delete user@otherbox:/media/squash/etc/audit/rules.d/ /etc/audit/rules.d/
user@otherbox's password: 

root@hedgehog:/tmp# rsync -avP --delete user@otherbox:/media/squash/etc/sudoers.d/ /etc/sudoers.d/
user@otherbox's password: 

root@hedgehog:/tmp# chmod 400 /etc/sudoers.d/*
```

18. Set capabilities and symlinks for network capture programs to be used by the unprivileged user:

commands:

```
chown root:netdev /usr/sbin/netsniff-ng && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng
chown root:netdev /opt/zeek/bin/zeek && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/zeek/bin/zeek
chown root:netdev /sbin/ethtool && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool
chown root:netdev /opt/zeek/bin/capstats && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /opt/zeek/bin/capstats
chown root:netdev /usr/bin/tcpdump && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump
chown root:netdev /opt/arkime/bin/capture && \
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/arkime/bin/capture

ln -s -f /opt/zeek/bin/zeek /usr/local/bin/
ln -s -f /usr/sbin/netsniff-ng /usr/local/bin/
ln -s -f /usr/bin/tcpdump /usr/local/bin/
ln -s -f /opt/arkime/bin/capture /usr/local/bin/
ln -s -f /opt/arkime/bin/npm /usr/local/bin
ln -s -f /opt/arkime/bin/node /usr/local/bin
ln -s -f /opt/arkime/bin/npx /usr/local/bin
```

example:

```
root@hedgehog:/tmp# chown root:netdev /usr/sbin/netsniff-ng && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip CAP_SYS_ADMIN+eip' /usr/sbin/netsniff-ng
root@hedgehog:/tmp# chown root:netdev /opt/zeek/bin/zeek && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/zeek/bin/zeek
root@hedgehog:/tmp# chown root:netdev /sbin/ethtool && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /sbin/ethtool
root@hedgehog:/tmp# chown root:netdev /opt/zeek/bin/capstats && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /opt/zeek/bin/capstats
root@hedgehog:/tmp# chown root:netdev /usr/bin/tcpdump && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump
root@hedgehog:/tmp# chown root:netdev /opt/arkime/bin/capture && \
>   setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip CAP_IPC_LOCK+eip' /opt/arkime/bin/capture
root@hedgehog:/tmp# ln -s -f /opt/zeek/bin/zeek /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /usr/sbin/netsniff-ng /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /usr/bin/tcpdump /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/capture /usr/local/bin/
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/npm /usr/local/bin
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/node /usr/local/bin
root@hedgehog:/tmp# ln -s -f /opt/arkime/bin/npx /usr/local/bin
```

19. Back up unprivileged user sensor-specific config and scripts:
    - `mv /opt/sensor/ /opt/sensor_upgrade_backup_$(date +%Y-%m-%d)`

20. Grab unprivileged user sensor-specific config and scripts from our mount of the ISO using `rsync` and change its ownership to the unprivileged user:
```
root@hedgehog:/tmp# rsync -av user@otherbox:/media/squash/opt/sensor /opt/
user@otherbox's password: 
receiving incremental file list
created directory ./opt
sensor/
[...]

sent 1,244 bytes  received 1,646,409 bytes  470,758.00 bytes/sec
total size is 1,641,629  speedup is 1.00

root@hedgehog:/tmp# chown -R sensor:sensor /opt/sensor*

root@hedgehog:/tmp# ls -l /opt/ | grep sensor
drwxr-xr-x  4 sensor sensor  4096 May  6 22:00 sensor
drwxr-x---  4 sensor sensor  4096 May  8 14:33 sensor_upgrade_backup_2020-05-08
```

21. Leave the root shell and `cd` to `/opt`
```
root@hedgehog:~# exit
logout

sensor@hedgehog:~$ whoami
sensor

sensor@hedgehog:~$ cd /opt
```

22. Compare the old and new `control_vars.conf` files
```
sensor@hedgehog:opt$ diff sensor_upgrade_backup_2020-05-08/sensor_ctl/control_vars.conf sensor/sensor_ctl/control_vars.conf 
1,2c1,2
< export CAPTURE_INTERFACE=enp0s3
< export CAPTURE_FILTER="not port 5044 and not port 5601 and not port 8005 and not port 9200 and not port 9600"
---
> export CAPTURE_INTERFACE=xxxx
> export CAPTURE_FILTER=""
4c4
[...]
```

Examine the differences. If there aren't any new `export` variables, then you're probably safe to just replace the default version of `control_vars.conf` with the backed-up version:

```
sensor@hedgehog:opt$ cp sensor_upgrade_backup_2020-05-08/sensor_ctl/control_vars.conf sensor/sensor_ctl/control_vars.conf 
cp: overwrite 'sensor/sensor_ctl/control_vars.conf'? y
```

If there are major differences or new variables, continue on to the next step, in a minute you'll need to run `capture-config` to configure from scratch anyway.

23. Restore certificates/keystores for forwarders from the backup `sensor_ctl` path to the new one
```
sensor@hedgehog:opt$ for BEAT in filebeat miscbeat; do cp /opt/sensor_upgrade_backup_2020-05-08/sensor_ctl/$BEAT/data/* /opt/sensor/sensor_ctl/$BEAT/data/; done

sensor@hedgehog:opt$ cp /opt/sensor_upgrade_backup_2020-05-07/sensor_ctl/filebeat/{ca.crt,client.crt,client.key} /opt/sensor/sensor_ctl/logstash-client-certificates/
```

24. Despite what we just did, you may consider running `capture-config` to re-configure [capture, forwarding, and autostart services](malcolm-hedgehog-e2e-iso-install.md#HedgehogInstallAndConfig) from scratch anyway. You can use the backed-up version of `control_vars.conf` to refer back to as a basis for things you might want to restore (e.g., `CAPTURE_INTERFACE`, `CAPTURE_FILTER`, `PCAP_PATH`, `ZEEK_LOG_PATH`, your autostart settings, etc.).

25. Once you feel confident you've completed all of these steps, issue a reboot on the Hedgehog

## Post-upgrade

Once the Hedgehog has come back up, check to make sure everything is working:

* `/opt/sensor/sensor_ctl/status` should return `RUNNING` for the things you set to autorun (no `FATAL` errors)
* `sensorwatch` should show current writes to Zeek log files and PCAP files (depending on your configuration)
* `tail -f /opt/sensor/sensor_ctl/log/*` should show no egregious errors
* `zeek --version`, `zeek -N local` and `capture --version` ought to run and print out version information as expected
* if you are forwarding to a [Malcolm]({{ site.github.repository_url }}) aggregator, you should start seeing data momentarily