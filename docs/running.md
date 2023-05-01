# <a name="Running"></a>Running Malcolm

* [Running Malcolm](#Running)
    - [OpenSearch instances](opensearch-instances.md#OpenSearchInstance)
        + [Authentication and authorization for remote OpenSearch clusters](opensearch-instances.md#OpenSearchAuth)
    - [Starting Malcolm](#Starting)
    - [Stopping and restarting Malcolm](#StopAndRestart)
    - [Clearing Malcolm's data](#Wipe)
    - [Temporary read-only interface](#ReadOnlyUI)

## <a name="Starting"></a>Starting Malcolm

[Docker compose](https://docs.docker.com/compose/) is used to coordinate running the Docker containers. To start Malcolm, navigate to the directory containing `docker-compose.yml` and run:
```
$ ./scripts/start
```
This will create the containers' virtual network and instantiate them, then leave them running in the background. The Malcolm containers may take a several minutes to start up completely. To follow the debug output for an already-running Malcolm instance, run:
```
$ ./scripts/logs
```
You can also use `docker stats` to monitor the resource utilization of running containers.

## <a name="StopAndRestart"></a>Stopping and restarting Malcolm

You can run `./scripts/stop` to stop the docker containers and remove their virtual network. Alternatively, `./scripts/restart` will restart an instance of Malcolm. Because the data on disk is stored on the host in docker volumes, doing these operations will not result in loss of data. 

Malcolm can be configured to be automatically restarted when the Docker system daemon restart (for example, on system reboot). This behavior depends on the [value](https://docs.docker.com/config/containers/start-containers-automatically/) of the [`restart:`](https://docs.docker.com/compose/compose-file/#restart) setting for each service in the `docker-compose.yml` file. This value can be set by running [`./scripts/configure`](malcolm-config.md#ConfigAndTuning) and answering "yes" to "`Restart Malcolm upon system or Docker daemon restart?`."

## <a name="Wipe"></a>Clearing Malcolm's data

Run `./scripts/wipe` to stop the Malcolm instance and wipe its OpenSearch database (**including** [index snapshots and management policies](index-management.md#IndexManagement) and [alerting configuration](alerting.md#Alerting)).

## <a name="ReadOnlyUI"></a>Temporary read-only interface

To temporarily set the Malcolm user interaces into a read-only configuration, run the following commands from the Malcolm installation directory.

First, to configure [Nginx](https://nginx.org/) to disable access to the upload and other interfaces for changing Malcolm settings, and to deny HTTP methods other than `GET` and `POST`:

```
docker-compose exec nginx-proxy bash -c "cp /etc/nginx/nginx_readonly.conf /etc/nginx/nginx.conf && nginx -s reload"
```

Second, to set the existing OpenSearch data store to read-only:

```
docker-compose exec dashboards-helper /data/opensearch_read_only.py -i _cluster
```

These commands must be re-run every time you restart Malcolm.

Note that after you run these commands you may see an increase of error messages in the Malcolm containers' output as various background processes will fail due to the read-only nature of the indices. Additionally, some features such as Arkime's [Hunt](arkime.md#ArkimeHunt) and [building your own visualizations and dashboards](dashboards.md#BuildDashboard) in OpenSearch Dashboards will not function correctly in read-only mode.