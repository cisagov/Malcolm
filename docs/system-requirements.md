# <a name="SystemRequirements"></a>Recommended system requirements

Malcolm runs on top of [Docker](https://www.docker.com/), which runs on recent releases of Linux, Apple [macOS](host-config-macos.md#HostSystemConfigMac), and [Microsoft Windows](host-config-windows.md#HostSystemConfigWindows) 10 and up. Malcolm can also be deployed with [Podman](https://podman.io), or in the cloud [with Kubernetes](kubernetes.md#Kubernetes).

To quote the [Elasticsearch documentation](https://www.elastic.co/guide/en/elasticsearch/guide/current/hardware.html), "If there is one resource that you will run out of first, it will likely be memory." Malcolm requires a minimum of 8 CPU cores and 24 gigabytes of RAM on a dedicated server, but Malcolm developers recommend 16+ CPU cores and 32+ gigabytes of RAM for an optimal experience. Users will want as much available disk storage as possible (preferrably solid state storage), as the amount of PCAP data a machine can analyze and store will be limited by available storage space.

Arkime's wiki has documents ([here](https://github.com/arkime/arkime#hardware-requirements) and [here](https://github.com/arkime/arkime/wiki/FAQ#what-kind-of-capture-machines-should-we-buy) and [here](https://github.com/arkime/arkime/wiki/FAQ#how-many-elasticsearch-nodes-or-machines-do-i-need) and a [calculator here](https://arkime.com/estimators)) that may be helpful, although not everything in those documents will apply to a containerized setup such as Malcolm.

