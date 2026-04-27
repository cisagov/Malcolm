# Configuring Hedgehog for Standalone Use

Usually, Hedgehog Linux is configured to [communicate with a Malcolm aggregator](malcolm-hedgehog-e2e-iso-install.md#HedgehogCommConfig), forwarding logs containing session metadata about the network traffic it observes. However, there are also scenarios in which users may wish to have Hedgehog Linux monitor and capture network traffic in a standalone configuration without forwarding anything. This section outlines setting up Hedgehog Linux in that configuration.

1. Follow the steps for [ISO Installation](malcolm-hedgehog-e2e-iso-install.md#ISOInstallMalcolm) and configuring the [desktop environment](malcolm-hedgehog-e2e-iso-install.md#MalcolmDesktop), [network interfaces](malcolm-hedgehog-e2e-iso-install.md#NetConf), and [hostname, time sync, and SSH access](malcolm-hedgehog-e2e-iso-install.md#MalcolmTimeSync) as usual.
2. Run [`./scripts/configure`](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig), paying special attention to the following [menu items](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems).
    * **Run Profile Settings**:
        - Set all **Forward...** options to **No**.
        - The values for **Logstash Host**, **Malcolm Reachback ACL**, **Primary Document Store**, and **Remote Malcolm Hostname or IP** will not be used, so they can be left at their defaults.
    * **Clean Up Artifacts**:
        - Unless users are actively monitoring the size of the artifacts generated on the sensor, [disk usage](malcolm-config.md#DiskUsage) will eventually exceed its storage capacity.
        - Select **Y** for **Clean Up Artifacts**.
        - Under **Clean Up Artifacts Settings**, set **Prune Oldest Logs** and **Prune Oldest PCAP** to **Yes**, which will cause Hedgehog to delete the oldest network traffic artifacts (logs and PCAP files, respectively) when the disk is nearly full.
        - If Hedgehog is performing [automatic file extraction and scanning](file-scanning.md#ZeekFileExtraction) (configurable under **Enable Zeek Analysis** → **Zeek Analysis Settings** → **File Extraction**), the total allowed size of extracted files can be capped with either the **Extracted File Percent Threshold** or **Extracted File Size Threshold** settings.
    * Set **Enable Arkime Analysis** to **No**.
    * Set **NetBox Mode** to **Disabled**.
    * Set **Capture Live Network Traffic** to **Yes**.
    * **Capture Live Network Traffic Settings**:
        - Set **Analyze Live Traffic with Suricata** to **Yes** to record Suricata alerts in [EVE JSON format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
        - Set **Analyze Live Traffic with Zeek** to **Yes** to generate Zeek logs according to the **Zeek Analysis Settings** found on the main menu.
        - Set **Capture Live Traffic with Arkime** to **No**, as Arkime `capture` *requires* a connection to a remote data store.
        - Set *either* **Capture Live Traffic with netsniff-ng** or **Capture Live Traffic with tcpdump** to **Yes** to generate PCAP files of observed network traffic. netsniff-ng performs slightly better than tcpdump for high-performance sniffing on high-speed interfaces; otherwise, it does not matter which is used.
        - Set **Capture Interface(s)** and **Capture Filter** (if needed) as usual.
    * **Save and Continue** to apply the settings.
3. Edit the `./config/filebeat.env` file and add `FILEBEAT_MAIN_LOGS=false` to the end of that file.
4. Edit the `./config/opensearch.env` file and set `OPENSEARCH_URL` to empty (e.g., `OPENSEARCH_URL=`).
5. Run [`./scripts/auth_setup`](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) and select **all**.
    * Select **Yes** for **Store username/password for OpenSearch/Elasticsearch instance** and provide values for both username and password. The values themselves do not matter and will not be used, but for now, there are certain startup checks that require them to be present.
    * Select **Yes** for **Regenerate internal passwords for Valkey**.
    * Select **No** for **Store password hash secret for Arkime viewer cluster**.
    * Select **No** for **Receive client certificates from Malcolm**.
6. Open a terminal and run `touch ~/Malcolm/filebeat/certs/{ca.crt,client.crt,client.key}`. The contents of these files do not matter, but for now, they must exist for Malcolm to start.

Hedgehog can now be [started](running.md#Starting), [stopped or restarted](running.md#StopAndRestart) in the usual ways. Artifacts (Zeek logs, Suricata logs, PCAP files, etc.) will be stored as [configured under the **Default Storage Location Settings**](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems) for manual retrieval and analysis later.

See [**Tuning**](live-analysis.md#LiveAnalysisTuning) for more information about fine-tuning live traffic capture performance.
