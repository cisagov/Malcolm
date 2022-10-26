<?php
if (isset($_POST['save-state'])) {
  shell_exec('/usr/bin/supervisorctl -c /etc/supervisor/netbox/supervisord.conf restart netbox:initialization');
  $output = shell_exec('/usr/bin/supervisorctl -c /etc/supervisor/logstash/supervisord.conf restart logstash');
  echo "<pre>$output</pre>";
}
?>
