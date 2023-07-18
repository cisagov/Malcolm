# <a name="AssetInteractionAnalysis"></a>Asset Interaction Analysis

* [Enriching network traffic metadata via NetBox lookups](#NetBoxEnrichment)
* [Compare and highlight discrepancies between NetBox inventory and observed network traffic](#NetBoxCompare)
* Populating the NetBox inventory
    - [Manually](#NetBoxPopManual)
    - [Via passively-gathered network traffic metadata](#NetBoxPopPassive)
    - [Via active discovery](#NetBoxPopActive)
* [Compare NetBox inventory with database of known vulnerabilities](#NetBoxVuln)
* [Backup and restore](#NetBoxBackup)

Malcolm provides an instance of [NetBox](https://netbox.dev/), an open-source "solution for modeling and documenting modern networks." The NetBox web interface is available at at **https://localhost/netbox/** if connecting locally.

The design of a potentially deeper integration between Malcolm and Netbox is a [work in progress](https://github.com/idaholab/Malcolm/issues/131).

Please see the [NetBox page on GitHub](https://github.com/netbox-community/netbox), its [documentation](https://docs.netbox.dev/en/stable/) and its [public demo](https://demo.netbox.dev/) for more information.

## <a name="NetBoxEnrichment"></a>Enriching network traffic metadata via NetBox lookups

As Zeek logs and Suricata alerts are parsed and enriched (if the `LOGSTASH_NETBOX_ENRICHMENT` [environment variable in `./config/logstash.env`](malcolm-config.md#MalcolmConfigEnvVars) is set to `true`), the NetBox API will be queried for the associated hosts' information. If found, the information retrieved by NetBox will be used to enrich these logs through the creation of the following new fields. See [the NetBox API](https://demo.netbox.dev/api/docs/) documentation and [the NetBox documentation](https://demo.netbox.dev/static/docs/introduction/) for more information.

* `destination.…`
    - `destination.device.cluster` (`/virtualization/clusters/`) (for [Virtual Machine](https://demo.netbox.dev/static/docs/coe-functionality/virtualization/) device types)
    - [`destination.device.device_type`](https://demo.netbox.dev/static/docs/core-functionality/device-types/) (`/dcim/device-types/`)
    - `destination.device.id` (`/dcim/devices/{id}`)
    - `destination.device.manufacturer` (`/dcim/manufacturers/`)
    - `destination.device.name` (`/dcim/devices/`)
    - `destination.device.role` (`/dcim/device-roles/`)
    - [`destination.device.service`](https://demo.netbox.dev/static/docs/core-functionality/services/#service-templates) (`/ipam/services/`)
    - `destination.device.site` (`/dcim/sites/`)
    - `destination.device.url` (`/dcim/devices/`)
    - `destination.device.details` (full JSON object, [only with `LOGSTASH_NETBOX_ENRICHMENT_VERBOSE: 'true'`](malcolm-config.md#MalcolmConfigEnvVars))
    - `destination.segment.id` (`/ipam/vrfs/{id}`)
    - `destination.segment.name` (`/ipam/vrfs/`)
    - `destination.segment.site` (`/dcim/sites/`)
    - `destination.segment.tenant` (`/tenancy/tenants/`)
    - `destination.segment.url` (`/ipam/vrfs/`)
    - `destination.segment.details` (full JSON object, [only with `LOGSTASH_NETBOX_ENRICHMENT_VERBOSE: 'true'`](malcolm-config.md#MalcolmConfigEnvVars))
* `source.…` same as `destination.…`
* collected as `related` fields (the [same approach](https://www.elastic.co/guide/en/ecs/current/ecs-related.html) used in ECS)
    - `related.device_type`
    - `related.device_name`
    - `related.manufacturer`
    - `related.role`
    - `related.segment`
    - `related.service`
    - `related.site`

For Malcolm's purposes, both physical devices and virtualized hosts will be stored as described above: the `device_type` field can be used to distinguish between them.

NetBox has the concept of [sites](https://demo.netbox.dev/static/docs/core-functionality/sites-and-racks/). Sites can have overlapping IP address ranges. The value of the `NETBOX_DEFAULT_SITE` variable in [environment variable in `netbox-common.env`](malcolm-config.md#MalcolmConfigEnvVars) will be used as a query parameter for these enrichment lookups.

This feature was implemented as described in [idaholab/Malcolm#132](https://github.com/idaholab/Malcolm/issues/132).

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
    - [Virtual Routing and Forwarding (VRF)](https://docs.netbox.dev/en/stable/models/ipam/vrf/)
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

If the `LOGSTASH_NETBOX_AUTO_POPULATE` [environment variable in `./config/logstash.env`](malcolm-config.md#MalcolmConfigEnvVars) is set to `true`, [uninventoried](#NetBoxCompare) devices with private IP addresses (as defined in [RFC 1918](https://datatracker.ietf.org/doc/html/rfc1918) and [RFC 4193](https://datatracker.ietf.org/doc/html/rfc4193)) observed in known network segments will be automatically created in the NetBox inventory based on the information available. This value is set to `true` by answering **Y** to "Should Malcolm automatically populate NetBox inventory based on observed network traffic?" during [configuration](malcolm-config.md#ConfigAndTuning).

However, careful consideration should be made before enabling this feature: the purpose of an asset management system is to document the intended state of a network: with Malcolm configured to populate NetBox with the live network state, a network misconfiguration fault could result in an **incorrect documented configuration**.

Devices created using this autopopulate method will have their `status` field set to `staged`. It is recommended that users periodically review automatically-created devices for correctness and to fill in known details that couldn't be determined from network traffic. For example, the `manufacturer` field for automatically-created devices will be set based on the organizational unique identifier (OUI) determined from the first three bytes of the observed MAC address, which may not be accurate if the device's traffic was observed across a router. If possible, observed hostnames will be used in the naming of the automatically-created devices, falling back to the device manufacturer otherwise (e.g., `MYHOSTNAME @ 10.10.0.123` vs. `Schweitzer Engineering @ 10.10.0.123`).

Since device autocreation is based on IP address, information about network segments (including [virtual routing and forwarding (VRF)](https://docs.netbox.dev/en/stable/models/ipam/vrf/) and [prefixes](https://docs.netbox.dev/en/stable/models/ipam/prefix/)) must be first [manually specified](#NetBoxPopManual) in NetBox in order for devices to be automatically populated.

Although network devices can be automatically created using this method, [services](https://demo.netbox.dev/static/docs/core-functionality/services/#service-templates) should inventoried manually. The **Uninventoried Observed Services** visualization in the [**Zeek Known Summary** dashboard](dashboards.md#DashboardsVisualizations) can help users review network services to be created in NetBox.

See [idaholab/Malcolm#135](https://github.com/idaholab/Malcolm/issues/135) for more information on this feature.

## <a name="NetBoxPopActive"></a>Populate NetBox inventory via active discovery

See [idaholab/Malcolm#136](https://github.com/idaholab/Malcolm/issues/136).

## <a name="NetBoxVuln"></a>Compare NetBox inventory with database of known vulnerabilities

See [idaholab/Malcolm#134](https://github.com/idaholab/Malcolm/issues/134).

## <a name="NetBoxBackup"></a>Backup and Restore

The NetBox database may be backed up and restored using `./scripts/netbox-backup` and `./scripts/netbox-restore`, respectively. While Malcolm is running, run the following command from within the Malcolm installation directory to backup the entire NetBox database:

```
$ ./scripts/netbox-backup
NetBox configuration database saved to ('malcolm_netbox_backup_20230110-133855.gz', 'malcolm_netbox_backup_20230110-133855.media.tar.gz')
```

To clear the existing NetBox database and restore a previous backup, run the following command (substituting the filename of the `netbox_….gz` you wish to restore) from within the Malcolm installation directory while Malcolm is running:

```
./scripts/netbox-restore --netbox-restore ./malcolm_netbox_backup_20230110-125756.gz

```

Note that some of the data in the NetBox database is cryptographically signed with the value of the `SECRET_KEY` environment variable in the `./netbox/env/netbox-secret.env` environment file. A restored NetBox backup **will not work** if this value is different from when it was created.
