## Services for which Kubernetes manifests need to be developed

See **support Malcolm deployment with Kubernetes** [idaholab/Malcolm#149](https://github.com/idaholab/Malcolm/issues/149)

"Core services" are listed earlier in the list (i.e., we should probably approach the services roughly in this order).

* nginx-proxy
* opensearch
    - This is more complicated if we do OpenSearch in the container vs. [a remote instance](https://idaholab.github.io/Malcolm/docs/opensearch-instances.html#OpenSearchInstance). My recommendation is to do early development of this container with a remote instance (see the corresponding [`docker-compose.yml` section](https://github.com/idaholab/Malcolm/blob/0c14303f242ce1bae7e48b30ca7234c996930008/docker-compose-standalone.yml#L46-L68)) and then come back to it. We can still do the service/container with the `OPENSEARCH_LOCAL` variable set to `false`, which will cause the [`service_check_passthrough.sh`](https://github.com/idaholab/Malcolm/blob/main/shared/bin/service_check_passthrough.sh) script to get run at startup instead of the actual OpenSearch service. Note that [this requires](https://idaholab.github.io/Malcolm/docs/opensearch-instances.html#OpenSearchAuth) [LDAP authentication](https://idaholab.github.io/Malcolm/docs/authsetup.html#AuthLDAP), or to use basic authentication but ensure the accounts and passwords match on Malcolm and the remote OpenSearch instance.
* dashboards
* upload
* pcap-monitor
* arkime
* api
* dashboards-helper
* zeek
* suricata
* file-monitor
* filebeat
* freq
    - This one really doesn't have many dependencies on other services, so it could be done whenever.
* logstash
* name-map-ui
* netbox-redis
* netbox-redis-cache
* netbox-postgres
* netbox
* htadmin
    - Leaving this for towards the end since if we're using remote OpenSearch we'd be using LDAP anyway, and even if not we can use auth_setup to set a username/password. At the point this is done we'll no longer be able to use `configmap` for `nginx/htpasswd` (and `htadmin/config.ini`) as they'll need to be read/write.
* pcap-capture
    - Not sure what live capture looks like at all in this scenario: what would the capture interface be? So leaving this to the very end.
* zeek-live
    - See note for `pcap-capture`.
* suricata-live
    - See note for `pcap-capture`.