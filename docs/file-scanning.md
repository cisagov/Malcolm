# <a name="ZeekFileExtraction"></a>Automatic file extraction and scanning

Malcolm can leverage Zeek's knowledge of network protocols to automatically detect file transfers and extract those files from PCAPs as Zeek processes them. This behavior can be enabled globally by modifying the `ZEEK_EXTRACTOR_MODE` [variable in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars), or on a per-upload basis for PCAP files uploaded via the [browser-based upload form](upload.md#Upload) when **Analyze with Zeek** is selected.

To specify which files should be extracted, the following values are acceptable in `ZEEK_EXTRACTOR_MODE`:

* `none`: no file extraction
* `interesting`: extraction of files with mime types of common attack vectors
* `mapped`: extraction of files with recognized mime types
* `known`: extraction of files for which any mime type can be determined
* `all`: extract all files

Extracted files can be examined through any of the following methods:

* submitting file hashes to [**VirusTotal**](https://www.virustotal.com/en/#search); to enable this method, specify the `VTOT_API2_KEY` [environment variable in `zeek-secret.env`](malcolm-config.md#MalcolmConfigEnvVars)
* scanning files with [**ClamAV**](https://www.clamav.net/); to enable this method, set the `EXTRACTED_FILE_ENABLE_CLAMAV` [environment variable in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars) to `true`
* scanning files with [**Yara**](https://github.com/VirusTotal/yara); to enable this method, set the `EXTRACTED_FILE_ENABLE_YARA` [environment variable in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars) to `true`
* scanning PE (portable executable) files with [**Capa**](https://github.com/fireeye/capa); to enable this method, set the `EXTRACTED_FILE_ENABLE_CAPA` [environment variable in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars) to `true`

Files which are flagged via any of these methods will be logged as Zeek `signatures.log` entries, and can be viewed in the **Signatures** dashboard in OpenSearch Dashboards.

The `EXTRACTED_FILE_PRESERVATION` [environment variable in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars) determines the behavior for preservation of Zeek-extracted files:

* `quarantined`: preserve only flagged files in `./zeek-logs/extract_files/quarantine`
* `all`: preserve flagged files in `./zeek-logs/extract_files/quarantine` and all other extracted files in `./zeek-logs/extract_files/preserved`
* `none`: preserve no extracted files

The `EXTRACTED_FILE_HTTP_SERVER_…` [environment variables in `zeek.env`](malcolm-config.md#MalcolmConfigEnvVars) configure access to the Zeek-extracted files path through the means of a simple HTTPS directory server. Beware that Zeek-extracted files may contain malware. As such, the files may be optionally encrypted upon download (and decrypted using `openssl`, e.g., `openssl enc -aes-256-cbc -d -in example.exe.encrypted -out example.exe`)
