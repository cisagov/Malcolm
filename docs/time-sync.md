# <a name="ConfigTime"></a>Time synchronization

If you wish to set up time synchronization via [NTP](http://www.ntp.org/) or `htpdate`, open a terminal and run `system-quickstart`. Select **Continue**, then choose **Time Sync**. Here you can configure the operating system to keep its time synchronized with either an NTP server (using the NTP protocol), another Malcolm instance, or another HTTP/HTTPS server. On the next dialog, choose the time synchronization method you wish to configure.

If **htpdate** is selected, you will be prompted to enter the IP address or hostname and port of an HTTP/HTTPS server (for a Malcolm instance, port `9200` may be used) and the time synchronization check frequency in minutes. A test connection will be made to determine if the time can be retrieved from the server.

If *ntpdate* is selected, you will be prompted to enter the IP address or hostname of the NTP server.

Upon configuring time synchronization, a "Time synchronization configured successfully!" message will be displayed.