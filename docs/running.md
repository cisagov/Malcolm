# <a name="Running"></a>Running Malcolm

* [Running Malcolm](#Running)
    - [OpenSearch and Elasticsearch instances](opensearch-instances.md#OpenSearchInstance)
        + [Authentication and authorization for remote data store clusters](opensearch-instances.md#OpenSearchAuth)
    - [Starting Malcolm](#Starting)
    - [Stopping and restarting Malcolm](#StopAndRestart)
    - [Clearing Malcolm's data](#Wipe)
    - [Temporary read-only interface](#ReadOnlyUI)

## <a name="Starting"></a>Starting Malcolm

[Docker compose](https://docs.docker.com/compose/) is used to coordinate running the containers. To start Malcolm, navigate to the directory containing `docker-compose.yml` and run:
```
$ ./scripts/start
```
This will create the containers' virtual network and instantiate them, then leave them running in the background. The Malcolm containers may take several minutes to start up completely. To follow the debug output for an already-running Malcolm instance, run:
```
$ ./scripts/logs
```
You can also use `docker stats` to monitor the resource utilization of running containers.

## <a name="StopAndRestart"></a>Stopping and restarting Malcolm

You can run `./scripts/stop` to stop the containers and remove their virtual network. Alternatively, `./scripts/restart` will restart an instance of Malcolm. Because the data on disk is stored on the host in bind-mounted volumes, performing these operations will not result in loss of data.

Malcolm can be configured to automatically restart when the Docker system daemon restarts (for example, on system reboot). This behavior depends on the [value](https://docs.docker.com/config/containers/start-containers-automatically/) of the [`restart:`](https://docs.docker.com/compose/compose-file/#restart) setting for each service in the `docker-compose.yml` file. This value can be set via the **Malcolm Restart Policy** option of [`./scripts/configure`](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfigItems).

## <a name="Wipe"></a>Clearing Malcolm's data

Run `./scripts/wipe` to stop the Malcolm instance and wipe its OpenSearch database (**including** [index snapshots and management policies](index-management.md#IndexManagement) and [alerting configuration](alerting.md#Alerting)).

## <a name="ReingestPCAP"></a>Re-ingesting processed PCAPs

To **replay** PCAPs that are already in the host's `pcap/processed/` directory, first preview the selected captures (this is read-only):

```bash
./scripts/control.py --reingest-pcaps
```

The preview selects at most 10 original PCAP/PCAPNG files, ordered by name. To publish copies of those files into `pcap/upload/` for processing, explicitly request the operation:

```bash
./scripts/control.py --reingest-pcaps --reingest-apply --reingest-limit 10
```

The limit must be between 1 and 100. Only regular, header-verified PCAP/PCAPNG files directly under `pcap/processed/` are eligible; subdirectories, symlinks and previously replayed copies are skipped. Malcolm must use Docker Compose with `pcap-monitor`'s `/pcap` bind mount and the standard `processed` and `upload` subdirectories. The upload watcher processes these new files when running (or after Malcolm next starts).

Re-ingestion **does not wipe or reset OpenSearch indices, delete previously processed captures, or overwrite upload files**. It safely stages a complete copy before publishing it with a unique `reingest_` filename, which bypasses filename-based duplicate detection. As a result, re-ingestion can produce **duplicate indexed sessions** and adds a replay marker to filename-derived tags. The operation is intended for deliberate troubleshooting/reprocessing, not automatic periodic use; ensure sufficient free disk space and review the preview before applying. Kubernetes re-ingestion is not supported by this command.

## <a name="ReadOnlyUI"></a>Temporary read-only interface

To temporarily set the Malcolm user interfaces into read-only configuration, run the following commands from the Malcolm installation directory.

First, to configure [Nginx](https://nginx.org/) to disable access to the upload and other interfaces for changing Malcolm settings, and to deny HTTP methods other than `GET` and `POST`:

```
docker compose exec nginx-proxy bash -c "cp /etc/nginx/nginx_readonly.conf /etc/nginx/nginx.conf && nginx -s reload"
```

Second, to set the existing OpenSearch data store to read-only:

```
docker compose exec dashboards-helper /usr/local/bin/opensearch_read_only.py -i _cluster
```

These commands must be re-run every time Malcolm is restarted.

Note: after running these commands there may be an increase of error messages in the Malcolm containers' output as various background processes will fail due to the read-only nature of the indices. Additionally, some features such as Arkime's [Hunt](arkime.md#ArkimeHunt) and [building your own visualizations and dashboards](dashboards.md#BuildDashboard) in OpenSearch Dashboards will not function correctly in read-only mode.