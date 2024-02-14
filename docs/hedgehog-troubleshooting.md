# <a name="HedgehogTroubleshooting"></a>Appendix D - Troubleshooting

Should the sensor not function as expected, first try rebooting the device. If the behavior continues, here are a few things that may help you diagnose the problem (items which may require Linux command line use are marked with **†**)

* Stop / start services – Using the sensor's kiosk mode, attempt a **Services Stop** followed by a **Services Start**, then check **Sensor Status** to see which service(s) may not be running correctly.
* Sensor configuration file – See `/opt/sensor/sensor_ctl/control_vars.conf` for sensor service settings. It is not recommended to manually edit this file unless you are sure of what you are doing.
* Sensor control scripts – There are scripts under ``/opt/sensor/sensor_ctl/`` to control sensor services (eg., `shutdown`, `start`, `status`, `stop`, etc.)
* Sensor debug logs – Log files under `/opt/sensor/sensor_ctl/log/` may contain clues to processes that are not working correctly. If you can determine which service is failing, you can attempt to reconfigure it using the instructions in the Configure Capture and Forwarding section of this document.
* `sensorwatch` script – Running `sensorwatch` on the command line will display the most recently modified PCAP and Zeek log files in their respective directories, how much storage space they are consuming, and the amount of used/free space on the volumes containing those files.