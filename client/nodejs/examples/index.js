
const path = require('path');
const DICOM = require(path.join(__dirname,'/../lib/dicom'));

const HOST = '172.16.144.132';
const PORT = 8080;

const client = DICOM.client(HOST, PORT);

client.connect()
	.then(() => {
		return client.ping();
	}).then((res) => {
		console.log(res);

		return client.echo('hello, world!');
	}).then((res) => {
		console.log(res);

	}).catch(err => {
		console.error(err);
	});
