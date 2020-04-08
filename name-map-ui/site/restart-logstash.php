<?php
if (isset($_POST['save-state'])) {
  $output = shell_exec('/usr/bin/supervisorctl -c /etc/supervisor/logstash/supervisord.conf restart logstash');
  echo "<pre>$output</pre>";
}
?>
