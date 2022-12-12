# <a name="HostAndSubnetNaming"></a>Automatic host and subnet name assignment

* [Automatic host and subnet name assignment](host-and-subnet-mapping.md#HostAndSubnetNaming)
    - [Defining hostname and CIDR subnet names interface](host-and-subnet-mapping.md#NameMapUI)
    - [Applying mapping changes](host-and-subnet-mapping.md#ApplyMapping)
    - [IP/MAC address to hostname mapping](host-and-subnet-mapping.md#HostNaming)
    - [CIDR subnet to network segment name mapping](host-and-subnet-mapping.md#SegmentNaming)

## <a name="NameMapUI"></a>Defining hostname and CIDR subnet names interface

A **Host and Subnet Name Mapping** editor is available at [https://localhost/name-map-ui/](https://localhost/name-map-ui/) if you are connecting locally. Upon loading, the editor is populated from `net-map.json`. 

This editor provides the following controls:

* 🔎 **Search mappings** - narrow the list of visible items using a search filter
* **Type**, **Address**, **Name** and **Tag** *(column headings)* - sort the list of items by clicking a column header
* 📝 *(per item)* - modify the selected item
* 🚫 *(per item)* - remove the selected item
* 🖳 **host** / 🖧 **segment**, **Address**, **Name**, **Tag (optional)** and 💾 - save the item with these values (either adding a new item or updating the item being modified)
* 📥 **Import** - clear the list and replace it with the contents of an uploaded `net-map.json` file
* 📤 **Export** - format and download the list as a `net-map.json` file
* 💾 **Save Mappings** - format and store `net-map.json` in the Malcolm directory (replacing the existing `net-map.json` file)
* 🔁 **Restart Logstash** - restart log ingestion, parsing and enrichment

![Host and Subnet Name Mapping Editor](./images/screenshots/malcolm_name_map_ui.png)

## <a name="ApplyMapping"></a>Applying mapping changes

When changes are made to `net-map.json`, Malcolm's Logstash container must be restarted. The easiest way to do this is to restart malcolm via `restart` (see [Stopping and restarting Malcolm](running.md#StopAndRestart)) or by clicking the 🔁 **Restart Logstash** button in the [name mapping interface](#NameMapUI) interface.

Restarting Logstash may take several minutes, after which log ingestion will be resumed.

## <a name="HostNaming"></a>IP/MAC address to hostname mapping

The editor described above can be used to define names for network devices based on IP and/or MAC addresses in Zeek logs. A device is identified by its address(es), name, and, optionally, a tag which, if specified, must belong to a log for the matching to occur.

As Zeek logs are processed into Malcolm's OpenSearch instance, the log's source and destination IP and MAC address fields (`source.ip`, `destination.ip`, `source.mac`, and `destination.mac`, respectively) are compared against the address-to-name map. When a match is found, a new field is added to the log: `source.device` or `destination.device`, depending on whether the matching address belongs to the originating or responding host. If the third field (the "required tag" field) is specified, a log must also contain that value in its `tags` field in addition to matching the IP or MAC address specified in order for the corresponding `.device` field to be added.

`source.device` and `destination.device` may each contain multiple values. For example, if both a host's source IP address and source MAC address were matched by two different lines, `source.device` would contain the name from both matching lines.

## <a name="SegmentNaming"></a>CIDR subnet to network segment name mapping

The editor described above can be also used to define names for network segments based on IP addresses in Zeek logs. A network segment is defined by its CIDR-formatted subnet IP range(s), subnet name, and, optionally, a tag which, if specified, must belong to a log for the matching to occur.

As Zeek logs are processed into Malcolm's OpenSearch instance, the log's source and destination IP address fields (`source.ip` and `destination.ip`, respectively) are compared against the address-to-subnet map. When a match is found, a new field is added to the log: `source.segment` or `destination.segment`, depending on whether the matching address belongs to the originating or responding host. If the third field (the "required tag" field) is specified, a log must also contain that value in its `tags` field in addition to its IP address falling within the subnet specified in order for the corresponding `_segment` field to be added.

`source.segment` and `destination.segment` may each contain multiple values. For example, overlapping subnets are defined, `source.segment` would contain the subnet values for both if `source.ip` belonged to both subnets.

If both `source.segment` and `destination.segment` are added to a log, and if they contain different values, the tag `cross_segment` will be added to the log's `tags` field for convenient identification of cross-segment traffic. This traffic could be easily visualized using Arkime's **Connections** graph, by setting the **Src:** value to **Originating Network Segment** and the **Dst:** value to **Responding Network Segment**:

![Cross-segment traffic in Connections](./images/screenshots/arkime_connections_segments.png)

