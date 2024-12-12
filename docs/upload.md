# <a name="Upload"></a>Network traffic artifact upload

* [Network traffic artifact upload](#Upload)
    - [Tagging](#Tagging)
    - [NetBox site](#UploadNetBoxSite)

Malcolm serves a web browser-based upload form for uploading PCAP files and Zeek logs at **https://localhost/upload/** if connecting locally.

![Network traffic artifact upload](./images/screenshots/malcolm_upload.png)

Additionally, there is a writable `files` directory on an SFTP server served on port 8022 (e.g., `sftp://USERNAME@localhost:8022/files/` if connecting locally).

The types of files supported are:

* PCAP files (of mime type `application/vnd.tcpdump.pcap` or `application/x-pcapng`)
    - PCAPNG files are *partially* supported: Zeek is able to process PCAPNG files, but not all of Arkime's packet examination features work correctly
* Zeek logs (with a `.log` file extension) in archive files (`application/gzip`, `application/x-gzip`, `application/x-7z-compressed`, `application/x-bzip2`, `application/x-cpio`, `application/x-lzip`, `application/x-lzma`, `application/x-rar-compressed`, `application/x-tar`, `application/x-xz`, or `application/zip`)
    - because log fields may differ depending on Zeek's configuration, users are recommended to use [Zeek JSON format logs](https://docs.zeek.org/en/master/log-formats.html#zeek-json-format-logs) when generating Zeek logs outside of Malcolm to later be uploaded to Malcolm for procesing
    - where the Zeek logs are found in the internal directory structure in the archive file does not matter
* Microsoft Windows [event log files](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format) (with a `.evtx` file extension) uploaded directly or in archive files (`application/gzip`, `application/x-gzip`, `application/x-7z-compressed`, `application/x-bzip2`, `application/x-cpio`, `application/x-lzip`, `application/x-lzma`, `application/x-rar-compressed`, `application/x-tar`, `application/x-xz`, or `application/zip`)

Files uploaded via these methods are monitored and moved automatically to other directories for processing, generally within 1 minute of completion of the upload.

The upload UI features a readiness indicator at the bottom of the form. Hovering over this text reveals more details about the individual Malcolm components' [readiness](api-ready.md). When the minimal set of components required for ingestion are running, this indicator will read **✅ Ready to ingest data.** Clicking on the indicator will cause it to refresh. It's recommended to wait until Malcolm is ready before uploading artifacts for processing.

## <a name="Tagging"></a>Tagging

In addition to being processed for uploading, Malcolm events will be tagged according to the components of the filenames of the PCAP files or Zeek log archives files from which the events were parsed. For example, records created from a PCAP file named `ACME_Scada_VLAN10.pcap` would be tagged with `ACME`, `Scada`, and `VLAN10`. Tags are extracted from filenames by splitting on the characters `,` (comma), `-` (dash), and `_` (underscore). These tags are viewable and searchable (via the `tags` field) in Arkime and OpenSearch Dashboards. This behavior can be changed by modifying the `AUTO_TAG` [environment variable in `upload-common.env`](malcolm-config.md#MalcolmConfigEnvVars).

Tags may also be specified manually with the [browser-based upload form](#Upload).

## <a name="UploadNetBoxSite"></a>NetBox site

If NetBox was enabled during [configuration](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig), users may specify a NetBox [site](https://demo.netbox.dev/static/docs/core-functionality/sites-and-racks/) to associate the uploaded PCAP data using the dropdown to the right of the Tags input. See [**Asset Interaction Analysis**](asset-interaction-analysis.md#AssetInteractionAnalysis) for more information about NetBox.
