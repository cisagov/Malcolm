function deleteUser(user){
	if (confirm('Are you sure?')) {
		var posting = $.post("delete.php", { user: user}, function(data) {
			$( ".result" ).html( data );
			
			if (data=="success") {
				$( ".result" ).html("<p>User <em>"+user+"</em> deleted.</p>");
				$(".result").show( "fast" );
				$('.id-' + user).remove();

			} else {
				$( ".result" ).html("<p>An error occured.</p>");
			}
			
		} );			
	}     
 }

function setUserField(user, email, name) {
	$(".userfield").val(user);
	$(".emailfield").val(email);
	$(".namefield").val(name);
	$(".passwordfield").focus();
}
