# <a name="NewImage"></a>Adding a new service (Docker image)

A new service can be added to Malcolm by following the following steps:

1. Create a new subdirectory for the service (under the Malcolm working copy base directory) containing whatever source or configuration files are necessary to build and run the service
1. Create the service's Dockerfile in the [Dockerfiles](../Dockerfiles) directory of your Malcolm working copy
1. Add a new section for your service under `services:` in the `docker-compose.yml` and `docker-compose-standalone.yml` files
1. If you want to enable automatic builds for your service on GitHub, create a new [workflow](../.github/workflows/), using an existing workflow as an example

## <a name="NewImageFirewall"></a>Networking and firewall

If your service needs to expose a web interface to the user, you'll need to adjust the following files:

* Ensure your service's section in the `docker-compose` files uses the `expose` directive to indicate which ports its providing
* Add the service to the `depends_on` section of the `nginx-proxy` service in the `docker-compose` files
* Modify the configuration of the `nginx-proxy` container (in [`nginx/nginx.conf`](../nginx/nginx.conf)) to define `upstream` and `location` directives to point to your service

Avoid publishing ports directly from your container to the host machine's network interface if at all possible. The `nginx-proxy` container handles encryption and authentication and should sit in front of any user-facing interface provided by Malcolm.