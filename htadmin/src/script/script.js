function deleteUser(user) {
  if (confirm("Confirm deletion of: '" + user + "' user account?")) {

   // Use JQuery to POST the 'user' name to the delete.php page
    var posting = $.post("delete.php", { user: user}, function(data) {

      data_array = data.split("|");
      if (data_array.length > 1) {
        error_msg = data_array[1];
      } else {
        error_msg = "An error occurred trying to delete the: '" + user + "' account.";
      }

      if (data_array[0] == "success") {
        // Inject HTML into HTML elments w/ class name '.result'.
        // Note: There is a .result and .result2 class.  The .result2 class
        //   is used to display feedback messages..when deleting a username.
        $( ".result" ).html("");
        $(".result").show( "fast" );

        $( ".result2" ).html("<p>User <em>"+user+"</em> deleted.</p>");
        $(".result2").show( "fast" );
        $('.id-' + user).remove();    // Dynamically. remove the HTML element w/ specified class name.

      } else {
        alert("deleteUser: Error; data_array[0]=" + data_array[0] + "; " + "data_array[1]=" +  data_array[1]);
        $( ".result" ).html("<p> " + error_msg + "</p>");
        $(".result").show( "fast" );
      }

    } ); // end $.post()
  }
}

function setUserField(user, email, name) {
  $(".userfield").val(user);
  $(".emailfield").val(email);
  $(".namefield").val(name);
  $(".passwordfield").focus();
}
