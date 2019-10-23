<?php
#
# Insert an inline message into the HTML stream. The $alert_message var
# must have been previously defined.

echo "<div class='alert " . $alert_class . "'>";
echo "<p>" . $alert_message . "</p>";
echo "</div>"

?>
