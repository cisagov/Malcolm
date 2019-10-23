<?php
/**
 * Page model:
 * $users as an array of strings
 * $use_metadata true / false
 * $meta_map as an array of meta_model objects, index is the user name.
 */
?>
<?php

if (count ( $users ) == 0) {
	echo "<p>No users found!</p>";
} else {
	?>
<div class="panel panel-default">

	<table class="table">
		<thead>
			<tr>
				<th>Username</th>
			<?php
	if ($use_metadata) {
		?>
			<th>Email</th>
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
		if ($use_metadata) {
			$fieldjs = "onclick=\"setUserField('" . htmlspecialchars ( $user ) . "', '" . htmlspecialchars ( $meta_map [$user]->email ) . "', '" . htmlspecialchars ( $meta_map [$user]->name ) . "');\"";
		} else {
			$fieldjs = "onclick=\"setUserField('" . htmlspecialchars ( $user ) . "','','');\"";
		}
		
		echo "<tr class='id-" . htmlspecialchars ( $user ) . "' >";
		echo "<td scope='row' " . $fieldjs . ">" . htmlspecialchars ( $user ) . " </td>";
		if ($use_metadata && isset ( $meta_map [$user] )) {
			echo "<td scope='row'>" . htmlspecialchars ( $meta_map [$user]->email ) . "</td>";
			echo "<td scope='row'>" . htmlspecialchars ( $meta_map [$user]->name ) . "</td>";
		}
		echo "<td scope='row'><a class='btn btn-danger pull-right' " . "onclick=\"deleteUser('" . htmlspecialchars ( $user ) . "');\"" . "href='#' >Delete</a>" . "</li></td>";
	}
	?>
	</tbody>
	</table>

</div>
<p>Click on a user to edit.</p>
<?php
}
?>
