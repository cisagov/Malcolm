# <a name="Scanners"></a>Carved file scanners

Similar to the [PCAP processing pipeline](contributing-pcap.md#PCAP) described above, new tools can plug into Malcolm's [automatic file extraction and scanning](file-scanning.md#ZeekFileExtraction) to examine file transfers carved from network traffic.

When Zeek extracts a file it observes being transfered in network traffic, the `file-monitor` container picks up those extracted files and publishes to a [ZeroMQ](https://zeromq.org/) topic that can be subscribed to by any other process that wants to analyze that extracted file. In Malcolm at the time of this writing (as of the [v5.0.0 release](https://github.com/idaholab/Malcolm/releases/tag/v5.0.0)), currently implemented file scanners include ClamAV, YARA, capa and VirusTotal, all of which are managed by the `file-monitor` container. The scripts involved in this code are:

* [shared/bin/zeek_carve_watcher.py](../shared/bin/zeek_carve_watcher.py) - watches the directory to which Zeek extracts files and publishes information about those files to the ZeroMQ ventilator on port 5987
* [shared/bin/zeek_carve_scanner.py](../shared/bin/zeek_carve_scanner.py) - subscribes to `zeek_carve_watcher.py`'s topic and performs file scanning for the ClamAV, YARA, capa and VirusTotal engines and sends "hits" to another ZeroMQ sync on port 5988
* [shared/bin/zeek_carve_logger.py](../shared/bin/zeek_carve_logger.py) - subscribes to `zeek_carve_scanner.py`'s topic and logs hits to a "fake" Zeek signatures.log file which is parsed and ingested by Logstash
* [shared/bin/zeek_carve_utils.py](../shared/bin/zeek_carve_utils.py) - various variables and classes related to carved file scanning

Additional file scanners could either be added to the `file-monitor` service, or to avoid coupling with Malcolm's code you could simply define a new service as instructed in the [Adding a new service](contributing-new-image.md#NewImage) section and write your own scripts to subscribe and publish to the topics as described above. While that might be a bit of hand-waving, these general steps take care of the plumbing around extracting the file and notifying your tool, as well as handling the logging of "hits": you shouldn't have to really edit any *existing* code to add a new carved file scanner.

The `EXTRACTED_FILE_PIPELINE_DEBUG` and `EXTRACTED_FILE_PIPELINE_DEBUG_EXTRA` environment variables in the `docker-compose` files can be set to `true` to enable verbose debug logging from the output of the Docker containers involved in the carved file processing pipeline.