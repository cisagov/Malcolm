<?php
/**
 * Page model:
 * $users: as an array of strings
 * $use_metadata: true / false
 * $meta_map: as an array of meta_model objects; index is the username.
 */
?>
<?php

if (count ( $users ) == 0) {
  echo "<p>Error: No usernames found in the user account table (metadata)!</p>";

} else {
  ?>
<div class="panel panel-default">

  <table class="table">
    <thead>
      <tr>
        <th>Username</th>
  <?php
  #$use_metadata = False;    # For debug tests

  if ($use_metadata) {
  ?>
        <th>Email_Address</th>
        <th>Name</th>
  <?php
        }
  ?>
        <th>&nbsp;</th>
      </tr>
    </thead>
    <tbody>
  <?php

  foreach ( $users as $user ) {

    $display_metadata = ($use_metadata && isset ( $meta_map [$user] ));

    if ($display_metadata) { # The user's 'email address' and 'name' are available.
                        		 # The setUserField() Javascript function will update the form fields under the "Create or update user:" heading.
      $fieldjs = "onclick=\"setUserField('" . htmlspecialchars ( $user ) . "', '" . htmlspecialchars ( $meta_map [$user]->email ) .  "', '" . htmlspecialchars ( $meta_map [$user]->name ) . "');\"";
    } else {
      $fieldjs = "onclick=\"setUserField('" . htmlspecialchars ( $user ) . "','','');\"";
    }

    echo "<tr class='id-" . htmlspecialchars ( $user ) . "' >\n\n";
    echo "      <td scope='row' style='cursor:grab;' " . $fieldjs . ">" . htmlspecialchars ( $user ) . " </td>";

    if ($display_metadata) {
      echo "<td scope='row'>" . htmlspecialchars ( $meta_map [$user]->email ) . "</td>";
      echo "<td scope='row'>" . htmlspecialchars ( $meta_map [$user]->name ) . "</td>";
    }
                # An "href=#" will scroll up to the top of page.. when clicked. (Rather than jumping to element's 'id' tag..e.g. href="#some-id"
                # Call the Javascript deleteUser() funct. when the "Delete" button is clicked.
    if ($user == $ini['admin_user'] ) {
      echo "<td scope='row'>" . "</li></td>";
    } else {
      echo "<td scope='row'><a class='btn btn-danger pull-right' " . "onclick=\"deleteUser('" . htmlspecialchars ( $user ) . "');\"" . "href='#' >Delete</a>" . "</li></td>";
    }
  }
  ?>

  </tbody>
  </table>

</div>
<p>Click on a username to edit an account.</p>
<?php
}
?>
