#!/bin/javascript

var Sddc = require('sddc');
var iosched = require('iosched');

var sddc = new Sddc('wl2');

sddc.setInfo('Spirit', 'edger', false, 'www.edgeros.com', '1', 'ACOINFO');

sddc.setFilter(function(devid, addr) {
	return true; // Allow!
});

sddc.start();

setTimeout(function() {
	sddc.discover(); // Discover devices every minute
}, 60 * 1000);

sddc.discover();

sddc.on('found', function(devid, info) {
	console.log('found: devid: ' + devid + ' info: ' + JSON.stringify(info));
	sddc.invite(devid, function(error) {
		if (error) {
			console.error('Invite device error:', error.message);
		}
	});
});

sddc.on('join', function(devid, info) {
	console.log('join: devid: ' + devid + ' info: ' + JSON.stringify(info));
	let s = {
		str: 'message from edgeros!'
	};
	sddc.send(devid, s);
});

sddc.on('message', function(devid, data) {
	console.log('Msg:', JSON.stringify(data), 'recv from:', devid);
});

while (true) {
	iosched.poll();
}