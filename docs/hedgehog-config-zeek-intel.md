# <a name="HedgehogIntel"></a>Zeek Intelligence Framework

Hedgehog Linux's management of intel files is identical to what is done by a Malcolm instance's Zeek containers. Please see [Zeek Intelligence Framework](zeek-intel.md#ZeekIntel) in the main Malcolm documentation for more information. For Hedgehog Linux, the only deviations from what is outlined in that document are that some of the file locations are different than they are on a Malcolm instance:

* the `ZEEK_INTEL_REFRESH_CRON_EXPRESSION` environment variable can be found in `/opt/sensor/sensor_ctl/control_vars.conf`
* the `./zeek/intel` directory is `/opt/sensor/sensor_ctl/zeek/intel`
* to manually refresh the Zeek intel files instead of waiting for the interval specified by `ZEEK_INTEL_REFRESH_CRON_EXPRESSION`, run `/opt/zeek/bin/zeek_intel_setup.sh true`