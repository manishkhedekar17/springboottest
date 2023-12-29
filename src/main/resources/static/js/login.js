function getAuth() {
	var l = window.location;
	var base_url = l.protocol + "//" + l.host + "/" + l.pathname.split('/')[1];
	var serviceUrl = base_url + "/auth";

	window.open(serviceUrl, '_blank');
	// $.ajax({
	// url : serviceUrl,
	// type : 'get',
	// }).done(function(data) {
	// console.log(data);
	// });
}