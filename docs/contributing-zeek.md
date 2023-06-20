# <a name="Zeek"></a>Zeek

## <a name="LocalZeek"></a>`local.zeek`

Some Zeek behavior can be tweaked through the use of [environment variables](malcolm-config.md#MalcolmConfigEnvVars) in the `.env` files beginning with `zeek…`.

Other changes to Zeek's behavior could be made by modifying [local.zeek]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/config/local.zeek) and either using a [bind mount](contributing-local-modifications.md#Bind) or [rebuilding](development.md#Build) the `zeek` Docker image with the modification. See the [Zeek documentation](https://docs.zeek.org/en/master/quickstart.html#local-site-customization) for more information on customizing a Zeek instance. Note that changing Zeek's behavior could result in changes to the format of the logs Zeek generates, which could break Malcolm's parsing of those logs, so exercise caution.

## <a name="ZeekPackage"></a>Adding a new Zeek package

The easiest way to add a new Zeek package to Malcolm is to add the git URL of that package to the `ZKG_GITHUB_URLS` array in [zeek_install_plugins.sh]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/shared/bin/zeek_install_plugins.sh) script and then [rebuilding](development.md#Build) the `zeek` Docker image. This will cause the package to be installed (via the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command-line tool). See [Parsing new Zeek logs](contributing-logstash.md#LogstashZeek) on how to process any new `.log` files if the package generates them.

## <a name="ContributingZeekIntel"></a>Zeek Intelligence Framework

See [Zeek Intelligence Framework](zeek-intel.md#ZeekIntel) in the Malcolm README for information on how to use Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) with Malcolm.