# <a name="Malcolm Analytics"></a>Analytics

- [Analytics](#analytics)
  - [Visualizations](#visualizations)
    - [Biomes](#biomes)
    - [Trees](#trees)
    - [Connections Tree](#connections-tree)
      - [Features](#features)
    - [SSH Tree](#ssh-tree)
    - [RDP Tree](#rdp-tree)
    - [Troubleshooting](#troubleshooting)
    - [Trends](#trends)
      - [BACnet](#bacnet)
      - [Modbus](#modbus)
      - [DNP3](#dnp3)
    - [Troubleshooting](#troubleshooting-1)
  - [Dashboards](#dashboards)
    - [IP Connections Tree Dashboard](#ip-connections-tree-dashboard)


The Analytics described here are developed by the internal Malcolm Analytics team to assist in highlighting aspects of a network. The purpose of this page is to explain aspects of visualizations or dashboards that may not be intuitive or that would benefit from more in-depth explanation of features.

All analytics are subject to overarching OpenSearch filters, including the Time Range filter and the search query bar.


## <a name="Visualizations"></a>Visualizations
* [Biomes](#Biomes)
* [Trees](#Trees)
    - [Connections Tree](#ConnTree)
    - [SSH Tree](#SSHTree)
    - [RDP Tree](#RDPTree)
* [Trends](#Trends)
    - [Bacnet](#Bacnet)
    - [Modbus](#Modbus)
    - [DNP3](#DNP3)

### <a name="Biomes"></a>Biomes
![Example Biomes Screenshot](./images/screenshots/biomes.png)

The purpose of the Biomes visualization is to help identify traffic that crosses layers of the Purdue Model, specifically traffic that connects the IT space and the ICS/OT space and bypasses the DMZ layer. 
 
An example use case is autopopulating your network inventory with Netbox and using subnet prefixes to organize your subnets into IT, OT, and DMZ zones or manually assigning devices in your inventory with the Purdue Zone field and then viewing the Biomes visualization to view the cross-zone traffic in your network. 

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/biomesFilePanel-Node.png" alt="Biomes File Panel Tooltip"></td>
<td>When hovering over a node, additional details will appear in the tooltip. Clicking on a purple node will open a file window on the left side of the screen to provide additional details about the file transfer.</td>
</tr>
<tr>
<td><img src="./images/screenshots/biomesFiltersZoomed.png" alt="Biomes Filters"></td>
<td>
<ul>
<li>The Min Connections slider filters out communications that do not satisfy the minimum number selected.</li>
<li>The IP Filter filters the nodes on the IP entered.</li>
<li>The Protocol Filter filters the nodes on the protocol entered.</li>
<li>The Exclude Subnet filter filters out nodes based on the subnet entered.</li>
<li>The Exclude Protocol filter filters out nodes based on the protocol entered.</li>
<li>The Show Files Only checkbox excludes all nodes without a file transfer associated.</li>
<li>The Line Type radio buttons allow the option to choose between two communication visuals to discern between uni- and bi-directional communications: double lines or arrows.</li>
<li>The IP Type radio buttons allow the option to choose between seeing Both IPv4 and IPv6 devices, only IPv4 devices, or only IPv6 devices.</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/biomesFiltersZoneZoomed.png" alt="Biome Zone Filters"></td>
<td>
<ul>
<li>The General &lt;-&gt; ICS Only button filters the nodes on communications between the General Network and ICS/OT zones only.</li>
<li>The DMZ &lt;-&gt; ICS button filters the nodes on communications between the DMZ and ICS/OT zones only.</li>
<li>The Full Chains Only button filters the nodes on communications that connect devices in all three zones (General Network, DMZ, and ICS/OT) in an unbroken chain only.</li>
<li>The Same Zone Links button excludes any node communications occurring within the same zone and only includes cross-zone traffic.</li>
</ul>
</td>
</tr>
</tbody>
</table>

### <a name="Trees"></a>Trees
All Trees share similar functionality and features.

### <a name="ConnTree"></a>Connections Tree
![Example Connections Tree Screenshot](./images/screenshots/analytics-conn-tree-1.png)

![Example Connections Tree (Mirrored) Screenshot](./images/screenshots/analytics-conn-tree-mirror-1.png)

The purpose of the Connections Tree visualization is to help identify potential avenues for lateral movement within a network, it allows you to visually focus in on Cyber Key Terrain (CKTs) and IP addresses that the user-defined root node communicates with.

Communications between nodes __A → B → C__ implies that lateral movement could potentially happen from node __A → C__

In Connections Tree, the root node is only ever the source IP. In Connections Tree (Mirrored), the root node is only ever a destination IP. The dashboard displaying these visualizations side-by-side is named **IP Connections Tree** (see documentation below at [Connections Tree Dashboard](#ConnTreeDash)).

An example use case is if an Engineering Workstation of interest is identified, or an unknown device, entering the IP address as the root node will visualize observed communications between the source device of interest and any other devices/IP addresses.

#### <a name="ConnTreeFeatures"></a>Features

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-tree-settings-key.png" alt="Tree Settings Key"></td>
<td>
<ul>
<li>Set the root IP address</li>
<li>Change the Tree height/depth up to 15 levels</li>
<li>Time Filter On only allows sequential connections to be displayed</li>
<li>Node Color provides several color options in order to take pretty screenshots</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-tree-avg-bytes.png" alt="Average Bytes Transferred key"></td>
<td>The Average Bytes transferred between nodes/devices are represented by a dotted link for communications transferring 0 bytes, and a solid line for communications transferring one or more bytes. The heavier the line, the greater the average number of bytes transferred between nodes/devices across all their communications. The line thicknesses are normalized; if a node is collapsed, all the other line thicknesses will be adjusted.</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-tree-node-hover.png" alt="Node hover key"></td>
<td>Hovering over a Node provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>IP address of the node/device</li>
<li>Detected MAC address of the node/device (if available)</li>
<li>Detected OUI of the node/device (if available)</li>
<li>Netbox-enriched name of the node/device</li>
<li>Netbox-enriched role of the node/device</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-tree-link-hover.png" alt="Link hover key"></td>
<td>Hovering over a Link line provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>Time of the first observed connection between the two nodes</li>
<li>Netbox-enriched name of the source segment of the communication</li>
<li>Netbox-enriched name of the destination segment of the communication</li>
<li>Average bytes transferred during communications between the nodes/devices</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-tree-conns-details-2.png" alt="Individual conns hover key"></td>
<td>When hovering over a link, additional details will appear in the top right corner, detailing the following for each individual communication between the src-dst IP pair:
<ul>
<li>The Connection State</li>
<li>The number of bytes transferred</li>
<li>The protocol(s) observed during the communication</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-tree-zoom-collapse.png" alt="Zoom/Collapsed Nodes"></td>
<td>Other quality-of-life features include:
<ul>
<li>You can collapse nodes to hide their communications by clicking on the node. Collapsed nodes are indicated by a dotted line encircling the node</li>
<li>You can zoom in and out on the tree, and click and drag the tree around in order to get a better look at crowded communications</li>
<li>Double-clicking in any blank space will reset the visual -- all nodes will be uncollapsed and the zoom will reset to default</li>
</ul>
</td>
</tr>
</tbody>
</table>

### <a name="SSHTree"></a>SSH Tree

Protocol-specific Trees have the same visual features as [Connections Tree](#ConnTree) (zoom, collapse, etc), but the enriched data is specific to SSH. This visualization is now located on the SSH dashboard.

![Example SSH Tree Screenshot](./images/screenshots/analytics-ssh-trees-1.png)

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-ssh-tree-node-hover.png" alt="SSH Node Hover Enrichment"></td>
<td>Hovering over a Node provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>IP address of the node/device</li>
<li>Detected MAC address of the node/device (if available)</li>
<li>Detected OUI of the node/device (if available)</li>
<li>Netbox-enriched name of the node/device</li>
<li>Netbox-enriched role of the node/device</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-ssh-tree-link-hover1.png" alt="SSH Link Hover Enrichment (cursor)"></td>
<td>Hovering over a Link line provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>Time of the first observed connection between the two nodes</li>
<li>Netbox-enriched name of the source segment of the communication</li>
<li>Netbox-enriched name of the destination segment of the communication</li>
<li>Average bytes transferred during communications between the nodes/devices</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-ssh-tree-link-hover2.png" alt="SSH Link Hover Enrichment (box)"></td>
<td>When hovering over a link, additional details will appear in the top right corner, detailing the following for each individual SSH session between the src-dst IP pair:
<ul>
<li>Whether the SSH session authenticated successfully</li>
<li>How many authorization attempts were made</li>
<li>The protocol(s) observed during the communication</li>
</ul>
</td>
</tr>
</tbody>
</table>

### <a name="RDPTree"></a>RDP Tree

Protocol-specific Trees have the same visual features as [Connections Tree](#ConnTree) (zoom, collapse, etc), but the enriched data is specific to RDP. This visualization is now located on the RDP dashboard.

![Example SSH Tree Screenshot](./images/screenshots/analytics-rdp-trees-1.png)

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-rdp-tree-node-hover1.png" alt="RDP Node hover enrichment"></td>
<td>Hovering over a Node provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>IP address of the node/device</li>
<li>Netbox-enriched name of the node/device</li>
<li>Netbox-enriched role of the node/device</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-rdp-tree-link-hover1.png" alt="RDP Link hover enrichment (cursor)"></td>
<td>Hovering over a Link line provides additional enrichment. Some of this enrichment is provided by Netbox, and will not display unless Netbox enrichment is turned on and populated.
<ul>
<li>Time of the first observed connection between the two nodes</li>
<li>The most common result of the RDP connections</li>
<li>The most commonly observed RDP session cookie</li>
<li>The security protocol being used</li>
<li>Netbox-enriched name of the source segment of the communication</li>
<li>Netbox-enriched name of the destination segment of the communication</li>
<li>The event ID of the first observed communication</li>
</ul>
</td>
</tr>
<tr>
<td>
<img src="./images/screenshots/analytics-rdp-tree-link-hover2.png" alt="RDP Link hover enrichment (box)"><br>
<img src="./images/screenshots/analytics-rdp-tree-link-hover3.png" alt="RDP Link hover enrichment (box)">
</td>
<td>When hovering over a link, additional details will appear in the top right corner, detailing the following for each individual RDP session between the src-dst IP pair:
<ul>
<li>The cookie for each individual RDP session</li>
<li>The security protocol for the RDP session (if observed)</li>
<li>The result of the RDP session</li>
</ul>
</td>
</tr>
</tbody>
</table>

### <a name="TreesTroubleshooting"></a>Troubleshooting

<!-- Bugs to squash later, and commonly encountered problems -->

If an IP address does not exist in the data being examined, a message will appear above the "Root IP" input bar stating "__IP address not found. Try adjusting the time range__".

This message can also appear due to object number limitations. Vega and Opensearch limit loading ten thousand object into the Vega table. If the IP address for certain exists elsewhere and cannot be found in Trees, consider limiting the time range further or utilize Malcolm's filters and reload the analytic.

If the IP address was initially loaded into the Vega table but not all of its connections/connection IP addresses were loaded an error bar will appear at the top of the analytic, stating "_Maximum data response reached. Data my be truncated. Try adjusting timeframe_".

If you encounter a bug, please submit a bug report or an issue to the Malcolm repository.

### <a name="Trends"></a>Trends

<!-- Colloquially known as "Squiggles" -->

Trends purpose is to standardize protocol behavior for analyst review. Analysts shouldn't necessarily have to understand what "normal" behavior looks like, or thoroughly understand the OT protocol, but given enough "normal" traffic, the analyst should be able to visually identify outlying traffic and can then take the data to an OT engineer to confirm whether the traffic is expected.

This analytic draws upon lessons learned from Stuxnet. The network traffic visualized on Trends should be unable to lie to an operator like an HMI may be able to.

The Trends graph plots the values for the PLc's addresses over time, as set by write functions for each of the covered OT protocols.

<table>
<tbody>
<tr>
<td>Who</td>
<td>Devices leveraging protocol</td>
</tr>
<tr>
<td>What</td>
<td>Behaviors being invoked on the devices</td>
</tr>
<tr>
<td>When</td>
<td>Session/scope of the device behavior</td>
</tr>
<tr>
<td>Where</td>
<td>Logical address on device</td>
</tr>
<tr>
<td>How</td>
<td>Function invoking behavior</td>
</tr>
</tbody>
</table>

The "Trends" Analytics share many features, described below.

<table>
<thead>
<tr>
<th>Protocol-agnostic features</th>
<th>Details</th>
</tr>
</thead>
<tbody>
<tr>
<td>PLC Address</td>
<td>On the left side of the analytic are the PLC addresses observed for the selected IP address. Click on it to hide all other PL addresses on the analytic, and double click in an empty space.</td>
</tr>
<tr>
<td>IP Selection</td>
<td>All IP addresses identified to be either the src or dst of the OT protocol are in a selection box on the right side of the analytic. Click one to select it.</td>
</tr>
<tr>
<td>Hover over node</td>
<td>Hover over a node for protocol-specific enrichment. See the sections below to see lists of the enrichment/information for each protocol.</td>
</tr>
<tr>
<td>Overview Selection graph</td>
<td>The overview selection graph shows a scaled-down version of all the PLC addresses for the selected IP address, you can zoom in on the primary graph by dragging and clicking to select a section on the Overview Selection Graph. To reset the view, double click on and blank space in the Overview Selection.</td>
</tr>
</tbody>
</table>

#### <a name="Bacnet"></a>BACnet

The BACnet Trends graph plots the __write_property + present_value__.

![BACnet Squiggles](./images/screenshots/analytics-bacnet-squiggles.png)

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-bacnet-node-hover.png" alt="BACnet Node hover enrichment"></td>
<td>BACnet-specific enrichment is available when you hover over the node.
<ul>
<li>Dataset denotes which log</li>
<li>The IP address/port of the communications</li>
<li>Which PLC address is being observed</li>
<li>The BACnet function</li>
<li>The value being read/written/changed</li>
<li>Date/Time of communication</li>
<li>The Malcolm Event ID tied to this communication</li>
</ul>
</td>
</tr>
</tbody>
</table>

#### <a name="Modbus"></a>Modbus

The Modbus Trends graph plots the __write_single_coil__, __write_single_register__, __write_multiple_coils__, and __write_multiple_registers__.

![Modbus Squiggles](./images/screenshots/analytics-modbus-squiggles.png)

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-modbus-node-hover.png" alt="Modbus Node hover enrichment"></td>
<td>Modbus-specific enrichment is available when you hover over the node.
<ul>
<li>Dataset denotes which log the data is pulled from</li>
<li>The IP address/port of the communications</li>
<li>Unit ID associated with the communication</li>
<li>Which PLC address is being observed</li>
<li>The Modbus function</li>
<li>The value being communicated</li>
<li>Date/Time of communication</li>
<li>The Malcolm Event ID tied to this communication</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-modbus-unit-select.png" alt="Modbus Unit Selection"></td>
<td>If there is more than one modbus Unit ID available for the selected IP address, the Unit Selection box will appear below the IP Selection.</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-vega-shapes2.png" alt="Modbus Node shapes"></td>
<td>Node shapes help differentiate between different Modbus functions at a glance.
<ul>
<li>Square - Single Register Write</li>
<li>Circle - Single Coil Write</li>
<li>Diamond - Multi-Register Write</li>
<li>Triangle - Multi-Coil Write</li>
</ul>
</td>
</tr>
</tbody>
</table>

#### <a name="DNP3"></a>DNP3
The DNP3 Trends graph plots the `OPERATE`, `DIRECT_OPERATE`, `RESPONSE`, and `SELECT` function sets.

![DNP3 Squiggles](./images/screenshots/analytics-dnp3-squiggles.png)

<table>
<thead>
<tr>
<th>Example Image</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="./images/screenshots/analytics-dnp3-node-hover.png" alt="DNP3 Node hover enrichment"></td>
<td>DNP3-specific enrichment is available when you hover over the node.
<ul>
<li>Dataset denotes which log this data node originates from</li>
<li>The IP address/port of the communications</li>
<li>Which PLC address is being observed</li>
<li>The DNP3 function</li>
<li>The Execute count</li>
<li>The duration of the function in milliseconds</li>
<li>Date/Time of communication</li>
<li>The Malcolm Event ID tied to this communication</li>
</ul>
</td>
</tr>
<tr>
<td><img src="./images/screenshots/analytics-vega-shapes.png" alt="DNP3 Node shape/size"></td>
<td>Node shapes help differentiate between different DNP3 functions at a glance.
<ul>
<li>Square - "OPERATE", "OPERATE:Pulse On", or "OPERATE:Pulse On:Trip"</li>
<li>Circle - OPERATE: unknown function</li>
<li>Diamond - "DIRECT_OPERATE:Latch On", "DIRECT_OPERATE_NR:Latch On", or "DIRECT_OPERATE:Pulse Off"</li>
<li>Triangle - "RESPONSE:Latch On", "RESPONSE:Pulse On:Trip", or "RESPONSE:Pulse Off:Close"</li>
<li>Upside-down Triangle - "SELECT:Latch On", "SELECT:Pulse On:Trip", or "SELECT:Pulse Off:Close"</li>
</ul>
        The size of the nodes also scale according to the execute_count.
</td>
</tr>
</tbody>
</table>

### <a name="TrendsTroubleshooting"></a>Troubleshooting

No known issues at this time. If you encounter a bug, please submit a bug report or an issue to the Malcolm repository.

## <a name="Dashboards"></a>Dashboards
* [IP Connections Tree Dashboard](#ConnTreeDash)
<!-- Include other Links to dashboards here -->

### <a name="ConnTreeDash"></a>IP Connections Tree Dashboard
![Example IP Connections Tree Screenshot](./images/screenshots/analytics-conn-tree-dashboard.png)

The IP Connections Tree dashboard's purpose is to help identify potential avenues for lateral movement within a network, it allowed you to visually focus in on Cyber Key Terrain (CKTs) and IP addresses that the user-defined root node communicates with.

The root node exhibits different behaviors in the two visuals. On the left, the root node is only ever the source of communications. On the right, the root node is only ever a destination for communications.

An example use case would be if a Engineering Workstation (EWS) was identified, inputting the IP address of the EWS in both the left and right visuals would allow an analyst to see what devices the EWS is communicating with, and what devices communicate with the EWS. Another devices of interest may include jump boxes, domain controllers, or PLCs.
