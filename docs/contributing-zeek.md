# <a name="Zeek"></a>Zeek

## <a name="LocalZeek"></a>`local.zeek`

Some Zeek behavior can be tweaked through the use of [environment variables](malcolm-config.md#MalcolmConfigEnvVars) in the `.env` files beginning with `zeek…`.

Other changes to Zeek's behavior could be made by modifying [local.zeek]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/config/local.zeek) and either using a [bind mount](contributing-local-modifications.md#Bind) or [rebuilding](development.md#Build) the `zeek` image with the modification. See the [Zeek documentation](https://docs.zeek.org/en/master/quickstart.html#local-site-customization) for more information on customizing a Zeek instance. Note that changing Zeek's behavior could result in changes to the format of the logs Zeek generates, which could break Malcolm's parsing of those logs, so exercise caution.

## <a name="ZeekPackage"></a>Adding a new Zeek package

Zeek packages are listed in [`zeek/zeek-packages.list`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/zeek-packages.list), one per line, with the branch, tag or commit to track and any environment variables the install needs. The build doesn't read the list directly: [`scripts/update_pins.py --zeek-packages --apply`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/update_pins.py) resolves each entry to a specific commit and writes [`zeek/zeek-packages.lock`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/zeek-packages.lock), and [`zeek_install_plugins.sh`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/zeek/scripts/zeek_install_plugins.sh) installs exactly what the lock file names (via the [`zkg`](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html) command-line tool) when the `zeek` image is [rebuilt](development.md#Build). See [Version Pinning](contributing-guide-code-provenance.md#VersionPinning) for how the list and lock file work together.

A package that only adds detections or enriches existing logs needs nothing more. If the package writes new `.log` files, see [Adding a new Zeek parser](contributing-zeek-parser.md#ZeekParser), which covers the whole process, from installing the package to building its dashboard.

## <a name="ContributingZeekIntel"></a>Zeek Intelligence Framework

See [Zeek Intelligence Framework](zeek-intel.md#ZeekIntel) in the Malcolm README for information on how to use Zeek's [Intelligence Framework](https://docs.zeek.org/en/master/frameworks/intel.html) with Malcolm.
