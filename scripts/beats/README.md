# Using Beats to forward host logs to Malcolm

Because Malcolm uses components of the open source data analysis platform [Elastic Stack](https://www.elastic.co/elastic-stack), it can accept various host logs sent from [Beats](https://www.elastic.co/beats/#the-beats-family), Elastic Stack's lightweight data shippers. These Beats generally include prebuilt Kibana dashboards for each of their respective data sets.

## Examples

Some examples include:

* [Auditbeat](https://www.elastic.co/beats/auditbeat)
    - [`auditd` logs](https://www.elastic.co/guide/en/beats/auditbeat/master/auditbeat-module-auditd.html) on Linux hosts
    - [file integrity monitoring](https://www.elastic.co/guide/en/beats/auditbeat/master/auditbeat-module-file_integrity.html) on Linux, macOS (Darwin) and Windows hosts
    - [system state](https://www.elastic.co/guide/en/beats/auditbeat/master/auditbeat-module-system.html) including host, process, login, package, socket and user information on Linux, with some data sets supported on macOS and Windows hosts (apparently not available with the [Open Source Elastic license](https://www.elastic.co/subscriptions))
* [Filebeat](https://www.elastic.co/beats/filebeat)
    - [system logs](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-system.html) (syslog and authentication logs) on Linux hosts
    - log output from [many products](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-modules.html) across Beats-supported platforms 
    - arbitrary textual [log files](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-log.html)
* [Metricbeat](https://www.elastic.co/beats/metricbeat)
    - [system](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-module-system.html) resource utilization and process information
    - metrics from [many products](https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-modules.html) across Beats-supported platforms
* [Packetbeat](https://www.elastic.co/beats/packetbeat)
    - host-based packet inspection for [many protocols](https://www.elastic.co/guide/en/beats/packetbeat/current/configuration-protocols.html) (supports `libpcap` on Linux, [macOS](https://formulae.brew.sh/formula/libpcap) and [Windows](https://nmap.org/npcap/); and `af_packet` on Linux)
* [Winlogbeat](https://www.elastic.co/downloads/beats/winlogbeat)
* [Custom](https://www.elastic.co/guide/en/beats/devguide/current/index.html) Beats
* [Community-contributed](https://www.elastic.co/guide/en/beats/devguide/current/community-beats.html) Beats

## Convenience configuration scripts and sample configurations

Two scripts are provided here for your convenience in configuring and running Beats to forward log data to Malcolm: [beat_config.py](./beat_config.py) and [beat_run.py](./beat_run.py). These Python scripts should run on Linux, macOS and Windows hosts with either Python 2 or Python 3.

Sample configurations are also provided for several beats for [Linux](./linux_vm_example) and [Windows](./windows_vm_example) hosts, as well as `Vagrantfile`s for setting up and running [VirtualBox](https://www.virtualbox.org/) VMs under [Vagrant](https://www.vagrantup.com/intro).

For further information, downloads, documentation or support for Beats, see the [Beats Platform Reference](https://www.elastic.co/guide/en/beats/libbeat/current/beats-reference.html) or the [Beats category](https://discuss.elastic.co/c/elastic-stack/beats) on the Elastic forums.

### Example: Windows configuration and run

```
PS C:\Program Files\winlogbeat> dir

    Directory: C:\Program Files\winlogbeat

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         7/27/2020   8:49 AM                kibana
d-----         7/27/2020   8:49 AM                module
-a----         3/26/2020   5:33 AM             41 .build_hash.txt
-a----         7/27/2020   8:50 AM          25799 beat_common.py
-a----         7/27/2020   8:50 AM           2525 beat_config.py
-a----         7/27/2020   8:50 AM           2244 beat_run.py
-a----         3/26/2020   5:32 AM         163122 fields.yml
-a----         7/27/2020   8:49 AM            878 install-service-winlogbeat.ps1
-a----         3/26/2020   4:44 AM          13675 LICENSE.txt
-a----         3/26/2020   4:44 AM         328580 NOTICE.txt
-a----         3/26/2020   5:33 AM            825 README.md
-a----         3/26/2020   5:33 AM            254 uninstall-service-winlogbeat.ps1
-a----         3/26/2020   5:33 AM       47818752 winlogbeat.exe
-a----         3/26/2020   5:32 AM          47900 winlogbeat.reference.yml
-a----         7/27/2020   8:50 AM           1349 winlogbeat.yml


PS C:\Program Files\winlogbeat> .\beat_config.py -c .\winlogbeat.yml -b winlogbeat

Append connectivity boilerplate to .\winlogbeat.yml? (y/N): y

Created winlogbeat keystore

Configure winlogbeat Elasticsearch connectivity? (Y/n): y

Enter Elasticsearch connection protocol (http or https) [https]: https

Enter Elasticsearch SSL verification (none (for self-signed certificates) or full) [none]: none

Enter Elasticsearch connection host: 172.15.0.41:9200

Configure winlogbeat Kibana connectivity? (Y/n): y

Enter Kibana connection protocol (http or https) [https]: https

Enter Kibana SSL verification (none (for self-signed certificates) or full) [none]: none

Enter Kibana connection host: 172.15.0.41:5601

Configure winlogbeat Kibana dashboards? (Y/n): y

Enter directory containing Kibana dashboards [C:\Program Files\winlogbeat\kibana]: C:\Program Files\winlogbeat\kibana

Enter HTTP/HTTPS server username: sensor
Enter password for sensor:
Enter password for sensor (again):

Generated keystore for winlogbeat
BEAT_DASHBOARDS_SSL_VERIFY
BEAT_OS_HOST
BEAT_OS_PROTOCOL
BEAT_OS_SSL_VERIFY
BEAT_DASHBOARDS_HOST
BEAT_HTTP_PASSWORD
BEAT_HTTP_USERNAME
BEAT_DASHBOARDS_ENABLED
BEAT_DASHBOARDS_PATH
BEAT_DASHBOARDS_PROTOCOL

PS C:\Program Files\winlogbeat> .\beat_run.py -c .\winlogbeat.yml -b winlogbeat

2020-07-27T09:00:17.472-0700    INFO    instance/beat.go:622    Home path: [C:\Program Files\winlogbeat] Config path: [C:\Program Files\winlogbeat] Data path: [C:\Program Files\winlogbeat] Logs path: [C:\Program Files\winlogbeat\logs]
2020-07-27T09:00:17.474-0700    INFO    instance/beat.go:630    Beat ID: c38487f0-ea87-477b-aa93-376eb40949f4
…
^C
KeyboardInterrupt
2020-07-27T09:00:24.783-0700    INFO    instance/beat.go:445    winlogbeat stopped.
```

### Example: Linux configuration and run

```
root@vagrant:/opt/filebeat# ls -l
total 4
-rw------- 1 root root 431 Jul 27 16:08 filebeat.yml

root@vagrant:/opt/filebeat# beat_config.py -c ./filebeat.yml -b filebeat

Append connectivity boilerplate to ./filebeat.yml? (y/N): y 

Create symlink to module path /usr/share/filebeat/module as /opt/filebeat/module? (Y/n): y

Created filebeat keystore

Configure filebeat Elasticsearch connectivity? (Y/n): y

Enter Elasticsearch connection protocol (http or https) [https]: https

Enter Elasticsearch SSL verification (none (for self-signed certificates) or full) [none]: none

Enter Elasticsearch connection host: 172.15.0.41:9200

Configure filebeat Kibana connectivity? (Y/n): y

Enter Kibana connection protocol (http or https) [https]: https

Enter Kibana SSL verification (none (for self-signed certificates) or full) [none]: none

Enter Kibana connection host: 172.15.0.41:5601

Configure filebeat Kibana dashboards? (Y/n): y

Enter directory containing Kibana dashboards [/usr/share/filebeat/kibana]: /usr/share/filebeat/kibana

Enter HTTP/HTTPS server username: sensor
Enter password for sensor: 
Enter password for sensor (again): 

Generated keystore for filebeat
BEAT_DASHBOARDS_PROTOCOL
BEAT_DASHBOARDS_SSL_VERIFY
BEAT_OS_PROTOCOL
BEAT_OS_SSL_VERIFY
BEAT_DASHBOARDS_ENABLED
BEAT_DASHBOARDS_PATH
BEAT_OS_HOST
BEAT_HTTP_PASSWORD
BEAT_HTTP_USERNAME
BEAT_DASHBOARDS_HOST

root@vagrant:/opt/filebeat# beat_run.py -c ./filebeat.yml -b filebeat

2020-07-27T16:12:43.270Z    INFO    instance/beat.go:622    Home path: [/opt/filebeat] Config path: [/opt/filebeat] Data path: [/opt/filebeat/data] Logs path: [/opt/filebeat/logs]
2020-07-27T16:12:43.270Z    INFO    instance/beat.go:630    Beat ID: 759019e0-705c-4a16-87a2-52e9a5f6e799
…
^C
KeyboardInterrupt
2020-07-27T16:13:10.816Z INFO    beater/filebeat.go:443  Stopping filebeat
```

# <a name="Footer"></a>Copyright

[Malcolm](https://github.com/idaholab/Malcolm) is Copyright 2022 Battelle Energy Alliance, LLC, and is developed and released through the cooperation of the Cybersecurity and Infrastructure Security Agency of the U.S. Department of Homeland Security.

See [`License.txt`](https://raw.githubusercontent.com/idaholab/Malcolm/main/License.txt) for the terms of its release.

### Contact information of author(s):

[malcolm@inl.gov](mailto:malcolm@inl.gov?subject=Malcolm)
