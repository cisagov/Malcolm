# <a name="NewImage"></a>Adding a new service (Docker image)

A new service can be added to Malcolm by following the following steps:

1. Create a new subdirectory for the service (under the Malcolm working copy base directory) containing whatever source or configuration files are necessary to build and run the service
1. Create the service's Dockerfile in the [Dockerfiles]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/Dockerfiles) directory of the Malcolm working copy
1. Add a new section for the service under `services:` in the `docker-compose.yml` and `docker-compose-standalone.yml` files
1. To enable automatic builds for the service on GitHub, create a new [workflow]({{ site.github.repository_url }}/tree/{{ site.github.build_revision }}/.github/workflows/), using an existing workflow as an example

## <a name="NewImageFirewall"></a>Networking and firewall

If the new service needs to expose a web interface to the user:

* Ensure the service's section in the `docker-compose` files uses the `expose` directive to indicate which ports its providing
* Add the service to the `depends_on` section of the `nginx-proxy` service in the `docker-compose` files
* Modify the configuration of the `nginx-proxy` container (in [`nginx/nginx.conf`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/nginx/nginx.conf)) to define `upstream` and `location` directives to point to the service

Avoid publishing ports directly from the container to the host machine's network interface if at all possible. The `nginx-proxy` container handles encryption and authentication and should sit in front of any user-facing interface provided by Malcolm.