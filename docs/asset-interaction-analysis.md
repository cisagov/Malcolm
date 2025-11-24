# <a name="AssetInteractionAnalysis"></a>Asset Interaction Analysis

* [Enriching network traffic metadata via NetBox lookups](#NetBoxEnrichment)
* [Compare and highlight discrepancies between NetBox inventory and observed network traffic](#NetBoxCompare)
* Populating the NetBox inventory
    - [Manually](#NetBoxPopManual)
    - [Via passively-gathered network traffic metadata](#NetBoxPopPassive)
        + [Subnets considered for autopopulation](#NetBoxAutoPopSubnets)
        + [Matching device manufacturers to OUIs](#NetBoxPopPassiveOUIMatch)
    - [Via active discovery](#NetBoxPopActive)
* [Compare NetBox inventory with database of known vulnerabilities](#NetBoxVuln)
* [Preloading NetBox inventory](#NetBoxPreload)
* [Backup and restore](#NetBoxBackup)

Malcolm can utilize an instance of [NetBox](https://netbox.dev/), an open-source "solution for modeling and documenting modern networks." Users may either use Malcolm's embedded NetBox instance (available at at **https://localhost/netbox/** if connecting locally), or Malcolm may connect to a remote NetBox instance not managed by Malcolm. This choice is made during configuration ([this example](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) or the NetBox section of [**Environment variable files**](malcolm-config.md#MalcolmConfigEnvVars) in the documentation).

The design of a potentially deeper integration between Malcolm and Netbox is a [work in progress](https://github.com/idaholab/Malcolm/issues/131).

Please see the [NetBox page on GitHub](https://github.com/netbox-community/netbox), its [documentation](https://docs.netbox.dev/en/stable/) and its [public demo](https://demo.netbox.dev/) for more information.

## <a name="NetBoxEnrichment"></a>Enriching network traffic metadata via NetBox lookups

As Zeek logs and Suricata alerts are parsed and enriched (if the `NETBOX_ENRICHMENT` [environment variable in `./config/netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars) is set to `true`), the NetBox API will be queried for the associated hosts' information. If found, the information retrieved by NetBox will be used to enrich these logs through the creation of the following new fields. See [the NetBox API](https://demo.netbox.dev/api/docs/) documentation and [the NetBox documentation](https://demo.netbox.dev/static/docs/introduction/) for more information.

* `destination.…`
    - `destination.device.cluster` (`/virtualization/clusters/`) (for [Virtual Machine](https://demo.netbox.dev/static/docs/coe-functionality/virtualization/) device types)
    - [`destination.device.device_type`](https://demo.netbox.dev/static/docs/core-functionality/device-types/) (`/dcim/device-types/`)
    - `destination.device.id` (`/dcim/devices/{id}`)
    - `destination.device.manufacturer` (`/dcim/manufacturers/`)
    - `destination.device.name` (`/dcim/devices/`)
    - `destination.device.role` (`/dcim/device-roles/`)
    - [`destination.device.service`](https://demo.netbox.dev/static/docs/core-functionality/services/#service-templates) (`/ipam/services/`)
    - `destination.device.site` (`/dcim/sites/`)
    - `destination.device.details` (full JSON object, [only with `NETBOX_ENRICHMENT_VERBOSE: 'true'`](malcolm-config.md#MalcolmConfigEnvVars))
    - `destination.segment.id` (`/ipam/prefixes/{id}`)
    - `destination.segment.name` (`/ipam/prefixes/{description}`)
    - `destination.segment.site` (`/dcim/sites/`)
    - `destination.segment.tenant` (`/tenancy/tenants/`)
    - `destination.segment.details` (full JSON object, [only with `NETBOX_ENRICHMENT_VERBOSE: 'true'`](malcolm-config.md#MalcolmConfigEnvVars))
* `source.…` same as `destination.…`
* collected as `related` fields (the [same approach](https://www.elastic.co/guide/en/ecs/current/ecs-related.html) used in ECS)
    - `related.device_type`
    - `related.device_id`
    - `related.device_name`
    - `related.manufacturer`
    - `related.role`
    - `related.segment`
    - `related.service`
    - `related.site`

For Malcolm's purposes, both physical devices and virtualized hosts will be stored as described above: the `device_type` field can be used to distinguish between them.

NetBox has the concept of [sites](https://demo.netbox.dev/static/docs/core-functionality/sites-and-racks/). Sites can have overlapping IP address ranges. The site to associate with network traffic can be specified when [PCAP is uploaded](upload.md#Upload), when configuring [live analysis](live-analysis.md#LiveAnalysis), and when [configuring forwarding from Hedgehog Linux](malcolm-hedgehog-e2e-iso-install.md#HedgehogCommConfig). If not otherwise specified, the value of the `NETBOX_DEFAULT_SITE` variable in [environment variable in `netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars) will be used for these enrichment lookups.

When NetBox enrichment is attempted for a log, the value `netbox` is automatically added to its `tags` field.

## <a name="NetBoxCompare"></a>Compare and highlight discrepancies between NetBox inventory and observed network traffic

As Malcolm cross-checks network traffic with NetBox's model (as described [above](#NetBoxEnrichment)), the resulting enrichment data (or lack thereof) can highlight devices and services observed in network traffic for which there is no corresponding entry in the list of inventoried assets.

These uninventoried devices and services are highlighted in two dashboards:

* **Zeek Known Summary** - this dashboard draws from the [periodically-generated `known_` logs and `software` logs](https://docs.zeek.org/en/master/logs/known-and-software.html) to provide a summary of the known devices and services in the network. The **Uninventoried Observed Services** and **Uninventoried Observed Hosts** tables show [services](https://docs.zeek.org/en/master/scripts/policy/protocols/conn/known-services.zeek.html) and [hosts](https://docs.zeek.org/en/master/scripts/policy/protocols/conn/known-hosts.zeek.html) (by IP address) that weren't found when searched via the NetBox API.

![Zeek Known Summary](./images/screenshots/dashboards_known_summary.png)

* **Asset Interaction Analysis** - this dashboard contains much of the same information from the **Zeek Known Summary** dashboard, but it is from a traffic standpoint rather than just an "observed" standpoint. The **Uninventoried Internal Source IPs**, **Uninventoried Internal Destination IPs** and **Uninventoried Internal Assets - Logs** tables highlight communications involving devices not found when searched via the NetBox API.

![Asset Interaction Analysis](./images/screenshots/dashboards_asset_interaction_analysis.png)

This feature was implemented as described in [idaholab/Malcolm#133](https://github.com/idaholab/Malcolm/issues/133).

## <a name="NetBoxPopManual"></a>Populate NetBox inventory manually

While the initial effort of populating NetBox's network segment and device inventory manually is high, it is the preferred method to ensure creation of an accurate model of the intended network design.

The [Populating Data](https://docs.netbox.dev/en/stable/getting-started/populating-data/) section of the [NetBox documentation](https://docs.netbox.dev/en/stable/) outlines mechanisms available to populate data in NetBox, including manual object creation, bulk import, scripting and the NetBox REST API.

The following elements of the NetBox data model are used by Malcolm for Asset Interaction Analysis.

* Network segments
    - [Prefixes](https://docs.netbox.dev/en/stable/models/ipam/prefix/)
* Network Hosts
    - [Devices](https://docs.netbox.dev/en/stable/models/dcim/device/)
        + [Device Types](https://docs.netbox.dev/en/stable/models/dcim/devicetype/)
        + [Device Roles](https://docs.netbox.dev/en/stable/models/dcim/devicerole/)
        + [Manufacturers](https://docs.netbox.dev/en/stable/models/dcim/manufacturer/)
    - [Virtual Machines](https://docs.netbox.dev/en/stable/models/virtualization/virtualmachine/)
    - [IP Addresses](https://docs.netbox.dev/en/stable/models/ipam/ipaddress/)
        + Can be assigned to devices and virtual machines
* Other
    - [Sites](https://docs.netbox.dev/en/stable/models/dcim/site/)

## <a name="NetBoxPopPassive"></a>Populate NetBox inventory via passively-gathered network traffic metadata

If the `NETBOX_AUTO_POPULATE` [environment variable in `./config/netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars) is set to `true`, [uninventoried](#NetBoxCompare) devices with private IP addresses (as defined in [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) and [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193)) observed in known network segments will be automatically created in the NetBox inventory based on the information available. This value is set to `true` by answering **Y** to "Should Malcolm automatically populate NetBox inventory based on observed network traffic?" during [configuration](malcolm-config.md#ConfigAndTuning).

However, careful consideration should be made before enabling this feature: the purpose of an asset management system is to document the intended state of a network: with Malcolm configured to populate NetBox with the live network state, a network misconfiguration fault could result in an **incorrect documented configuration**.

Devices created using this autopopulate method will include a `tags` value of `Autopopulated`. It is recommended that users periodically review automatically-created devices for correctness and to fill in known details that couldn't be determined from network traffic. For example, the `manufacturer` field for automatically-created devices will be set based on the organizational unique identifier (OUI) determined from the first three bytes of the observed MAC address, which may not be accurate if the device's traffic was observed across a router. If possible, observed hostnames (extracted from logs that provide a mapping of IP address to host name, such as Zeek's `dns.log`, `ntlm.log`, and `dhcp.log`) will be used in the naming of the automatically-created devices, falling back to the device manufacturer otherwise (e.g., `MYHOSTNAME` vs. `Schweitzer Engineering @ 10.10.0.123`).

Since device autocreation is based on IP address, information about network segments (IP [prefixes](https://docs.netbox.dev/en/stable/models/ipam/prefix/)) must be first [manually specified](#NetBoxPopManual) in NetBox in order for devices to be automatically populated. Users should populate the `description` field in the NetBox IPAM Prefixes data model to specify a name to be used for NetBox network segment autopopulation and enrichment, otherwise the IP prefix itself will be used.

Although network devices can be automatically created using this method, [services](https://demo.netbox.dev/static/docs/core-functionality/services/#service-templates) should inventoried manually. The **Uninventoried Observed Services** visualization in the [**Zeek Known Summary** dashboard](dashboards.md#DashboardsVisualizations) can help users review network services to be created in NetBox.

See [idaholab/Malcolm#135](https://github.com/idaholab/Malcolm/issues/135) for more information on this feature.

### <a name="NetBoxAutoPopSubnets"></a> Subnets considered for autopopulation

When [passive device autopopulation](#NetBoxPopPassive) is enabled, devices with addresses in private IP space will be autopopulated by default. You can control this behavior using the `NETBOX_AUTO_POPULATE_SUBNETS` [environment variable in `./config/netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars). This variable accepts a comma-separated list of private CIDR subnets, with the following logic:

* If left blank, *all private* IPv4 and IPv6 address ranges (as defined in [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) and [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193)) will be autopopulated.
* Use an exclamation point (`!`) before a CIDR to explicitly *exclude* that subnet.
* If only exclusions are listed, all private IPs are allowed *except* those excluded.
* If both inclusions and exclusions are listed:
    * Only addresses matching the allowed subnets will be considered.
    * Among those, any matching excluded subnets will be rejected.
* Network base and broadcast addresses (e.g., `.0` and `.255`) are not considered assignable and will be ignored.

This variable is especially useful for excluding dynamic address ranges such as those used by DHCP, which should generally not trigger autopopulation in NetBox. Since these addresses can change frequently and aren't tied to specific devices, including them could result in inaccurate or noisy inventory data. By fine-tuning which private subnets are included or excluded, users can ensure that only meaningful, typically static assignments are autopopulated.

#### Multiple NetBox Sites

Users may wish to apply different CIDR subnet filters for autopopulation within different NetBox sites. To support this, the `NETBOX_AUTO_POPULATE_SUBNETS` environment variable can accept multiple site-specific entries, each specifying a NetBox site name or numeric site ID, followed by a colon (`:`), and a comma-separated list of subnet rules (just like the single-site case described above). Multiple site entries should be separated by semicolons (`;`).

If no matching site-specific rule is found, the default rule — defined using an asterisk (`*`) as the site key, or by omitting the site name or ID — will be used as a fallback if present. If no fallback is defined, then all private IPs are autopopulated by default.

#### Examples

* `192.168.100.0/24`
    * Only allow addresses in `192.168.100.0/24`
* `!172.16.0.0/12`
    * Allow all private IPs *except* `172.16.0.0/12`
* `!10.0.0.0/8,10.0.10.0/24`
    * Exclude `10.0.0.0/8` generally, but *allow* `10.0.10.0/24` as an override
* `10.0.0.0/8,!10.0.10.0/16,10.0.10.5/32`
    * Allow all of `10.0.0.0/8` *except* `10.0.10.0/16`, *but still allow* `10.0.10.5`
* `!fc00::/7,fd12:3456:789a:1::/64`
    * Exclude all [ULA](https://en.wikipedia.org/wiki/Unique_local_address) IPv6 ranges, *except* a specific subnet
* `site1:10.0.0.0/8,!10.0.10.0/16,10.0.10.5/32;site2:!172.16.0.0/12;site3:!fc00::/7,fd12:3456:789a:1::/64;!192.168.0.0/16`
    * Specify different autopopulation rules for different NetBox sites

### <a name="NetBoxPopPassiveOUIMatch"></a> Matching device manufacturers to OUIs

Malcolm's NetBox inventory is prepopulated with a collection of [community-sourced device type definitions](https://github.com/netbox-community/devicetype-library) which can then be augmented by users [manually](#NetBoxPopManual) or through [preloading](#NetBoxPreload). During passive autopopulation device manufacturer is inferred from organizationally unique identifiers (OUIs), which make up the first three octets of a MAC address. The IEEE Standards Association maintains the [registry of OUIs](https://standards-oui.ieee.org/), which is not necessarily very internally consistent with how organizations specify the name associated with their OUI entry. In other words, there's not a foolproof programattic way for Malcolm to map MAC address OUI organization names to NetBox manufacturer names, barring creating and maintaining a manual mapping (which would be very large and difficult to keep up-to-date).

Malcolm's [NetBox lookup code]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/logstash/ruby/netbox_enrich.rb) used in the log enrichment pipeline attempts to match OUI organization names against the list of NetBox's manufacturers using ["fuzzy string matching"](https://en.wikipedia.org/wiki/Jaro%E2%80%93Winkler_distance), a technique in which two strings of characters are compared and assigned a similarity score between `0` (completely dissimilar) and `1` (identical). The `NETBOX_DEFAULT_FUZZY_THRESHOLD` [environment variable in `netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars) can be used to tune the threshold for determining a match. A fairly high value is recommended (above `0.85`; `0.95` is the default) to avoid autopopulating the NetBox inventory with devices with manufacturers that don't actually exist in the network being monitored.

Users may select between two behaviors for when the match threshold is not met (i.e., no manufacturer is found in the NetBox database which closely matches the OUI organization name). This behavior is specified by the `NETBOX_DEFAULT_AUTOCREATE_MANUFACTURER` [environment variable in `netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars):

* `NETBOX_DEFAULT_AUTOCREATE_MANUFACTURER=false` - the autopopulated device will be created with the manufacturer set to `Unspecified`
* `NETBOX_DEFAULT_AUTOCREATE_MANUFACTURER=true` - the autopopulated device will be created along with a new manufacturer entry in the NetBox database set to the OUI organization name

## <a name="NetBoxPopActive"></a>Populate NetBox inventory via active discovery

See [idaholab/Malcolm#136](https://github.com/idaholab/Malcolm/issues/136).

## <a name="NetBoxVuln"></a>Compare NetBox inventory with database of known vulnerabilities

See [idaholab/Malcolm#134](https://github.com/idaholab/Malcolm/issues/134).

## <a name="NetBoxPreload"></a>Preloading NetBox inventory

If Malcolm is using its own embedded NetBox instance, YML files in [`./netbox/preload`]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/netbox/preload/) under the Malcolm installation directory will be preloaded upon startup using the third-party [netbox-initializers](https://github.com/tobiasge/netbox-initializers) plugin. Examples illustrating the format of these YML files can be found at its [GitHub repository](https://github.com/tobiasge/netbox-initializers/tree/main/src/netbox_initializers/initializers/yaml).

## <a name="NetBoxBackup"></a>Backup and Restore

If Malcolm is using its own embedded NetBox instance, the NetBox database may be backed up and restored using `./scripts/netbox-backup` and `./scripts/netbox-restore`, respectively. While Malcolm is running, run the following command from within the Malcolm installation directory to backup the entire NetBox database:

```
$ ./scripts/netbox-backup
NetBox configuration database saved to ('malcolm_netbox_backup_20230110-133855.gz', 'malcolm_netbox_backup_20230110-133855.media.tar.gz')
```

To clear the existing NetBox database and restore a previous backup, run the following command (substituting the filename of the `netbox_….gz` to be restored) from within the Malcolm installation directory while Malcolm is running:

```
./scripts/netbox-restore --netbox-restore ./malcolm_netbox_backup_20230110-125756.gz

```

Users with a prior NetBox database backup (created with `netbox-backup` as described above) that they wish to be automatically restored on startup, that `.gz` file may be manually copied to the [`./netbox/preload`](#NetBoxPreload) directory. Upon startup that file will be extracted and used to populate the NetBox database, taking priority over the other preload files. This process does not remove the `.gz` file from the directory upon restoring it; it will be restored again on subsequent restarts unless manually removed.

Note that [network log enrichment](#NetBoxEnrichment) will fail while a restore is in progress (indicated with `HTTP/1.1 403` messages in the output of the `netbox` container in the Malcolm debug logs), but should resume once the restore process has completed.
