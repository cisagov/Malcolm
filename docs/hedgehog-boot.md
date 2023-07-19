# <a name="HedgehogBoot"></a>Boot

Each time the sensor boots, a grub boot menu will be shown briefly, after which the sensor will proceed to load.

## <a name="HedgehogKioskMode"></a>Kiosk mode

![Kiosk mode sensor menu: resource statistics](./images/hedgehog/images/kiosk_mode_sensor_menu.png)

The sensor automatically logs in as the sensor user account and runs in **kiosk mode**, which is intended to show an at-a-glance view of system resource utilization. Clicking the **☰** icon allows users to switch between the resource statistics view and the services view.

![Kiosk mode sensor menu: services](./images/hedgehog/images/kiosk_mode_services_menu.png)

The kiosk's services screen (designed with large clickable labels for small portable touch screens) can be used to start and stop essential services, get a status report of the currently running services, and clean all captured data from the sensor.

!["Clean Sensor" confirmation prompt before deleting sensor data](./images/hedgehog/images/kiosk_mode_wipe_prompt.png)

!["Sensor Status" report from the kiosk services menu](./images/hedgehog/images/kiosk_mode_status.png)