#!/bin/javascript

var Sddc = require('sddc');
var iosched = require('iosched');

var sddc = new Sddc('wl2');

sddc.setInfo({ name: 'Spirit', type: 'device', desc: 'www.edgeros.com', model: '1' }, 'xxx');

sddc.setFilter(function(devid, addr) {
    return true; // Allow!
});

sddc.start();

setTimeout(function() {
    sddc.discover(); // Discover devices every minute
}, 10 * 1000);

sddc.discover();

var t = new Timer();

var i = 0;

var iotpi_devid;

// Run the callback per second.
t.start(2000, 2000, () => {
    if (i % 3 == 0) {
        let s = {
            led1: true,
            led2: false,
            led3: false,
        };
        sddc.send(iotpi_devid, s);
    } else if (i % 3 == 1) {
        let s = {
            led1: false,
            led2: true,
            led3: false,
        };
        sddc.send(iotpi_devid, s);
    } else {
        let s = {
            led1: false,
            led2: false,
            led3: true,
        };
        sddc.send(iotpi_devid, s);
    }

    i++;
});

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

    iotpi_devid = devid;
});

sddc.on('message', function(devid, data) {
    console.log('Msg:', JSON.stringify(data), 'recv from:', devid);
});

sddc.on('update', function(devid, info) {
    console.log('Device update:', devid);
});

while (true) {
    iosched.poll();
}