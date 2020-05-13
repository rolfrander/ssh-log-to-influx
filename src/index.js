import log4js from 'log4js'
import net from 'net';
import ngeohash from 'ngeohash'

import {parseFilterlog,parseAuthFailedMessage} from './parser'
import doApiCall from './api';

let logger = log4js.getLogger();
logger.level = process.env.DEBUG_LEVEL || 'info';

const Influx = require('influx');
// InfluxDB Initialization.
const influx = new Influx.InfluxDB({
	host: process.env.INFLUX_URL,
	database: process.env.INFLUX_DB,
	username: process.env.INFLUX_USER || '',
	password: process.env.INFLUX_PWD || '',
	protocol: process.env.INFLUX_PROTOCOL || 'http'
});

influx.createDatabase(process.env.INFLUX_DB).catch((error) => {
	// if the database exists or the user doesn't have sufficient privileges, this will fail
	logger.warn(error.message);
});

const port = process.env.PORT || 7070;

const server = net.createServer();

server.on('connection', (socket) => {

	logger.info(`CONNECTED: ${socket.remoteAddress}:${socket.remotePort}`)

	socket.on('data', async (data) => {

		socket.end()
		socket.destroy()

		logger.debug('Received data', data.toString())

		var done = await receiveFilterlog(data.toString())
		if(!done) {
			done = await receiveSshLog(data.toString())
		}
	})

	socket.on('close', () => {
		logger.info(`CLOSED: ${socket.remoteAddress}:${socket.remotePort}`)
	});
});

server.listen(port, () => {
	logger.info(`TCP Server is running on port ${port}.`);
});

async function receiveSshLog(data) {
	const sshmsg = parseAuthFailedMessage(data)
	if(!sshmsg) {
		logger.debug("no match for ssh log");
		return false;
	}
	
	logger.debug(`Parsed ${sshmsg.username} ${sshmsg.ip} ${sshmsg.port}`)

	const ipLocation = await doApiCall(sshmsg.ip);

	if(!ipLocation) {
		logger.error('No data retrieved, cannot continue')
		return true;
	}

	const geohashed = ngeohash.encode(ipLocation.lat, ipLocation.lon);
	logger.debug(`Geohashing with lat: ${ipLocation.lat}, lon: ${ipLocation.lon}: ${geohashed}`)

	// Remove lon and lat from tags
	const {lon, lat, ...others} = ipLocation;

	influx.writePoints([
		{
			measurement: 'geossh',
			fields: {
				value: 1
			},
			tags: {
				geohash: geohashed,
				username: sshmsg.username,
				port: sshmsg.port,
				ip: sshmsg.ip,
				location: `${ipLocation.regionName}, ${ipLocation.city}`,
				...others
			}
		}
	]);

	return true;
}

async function receiveFilterlog(data) {
	const filterlog = parseFilterlog(data)
	if(!filterlog) {
		logger.debug("no match for filterlog log");
		return false;
	}

	if(filterlog.ip.startsWith("192.168.")) {
		logger.debug(`ignore private address: ${filterlog.ip}`);
		return true;
	}
	
	logger.debug(`Parsed filterlog ${filterlog.ip} ${filterlog.port}`)

	const ipLocation = await doApiCall(filterlog.ip);

	if(!ipLocation) {
		logger.error('No data retrieved, cannot continue')
		return true;
	}

	const geohashed = ngeohash.encode(ipLocation.lat, ipLocation.lon);
	logger.debug(`Geohashing with lat: ${ipLocation.lat}, lon: ${ipLocation.lon}: ${geohashed}`)

	// Remove lon and lat from tags
	const {lon, lat, ...others} = ipLocation;

	influx.writePoints([
		{
			measurement: 'filterlog',
			fields: {
				value: 1
			},
			tags: {
				geohash: geohashed,
				action: filterlog.action,
				port: filterlog.port,
				ip: filterlog.ip,
				proto: filterlog.proto,
				location: `${ipLocation.regionName}, ${ipLocation.city}`,
				...others
			}
		}
	]);

	return true;
}

