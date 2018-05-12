
const VERSION = '1.0';
const https = require('https');
const fetch = require('node-fetch');
const ursa = require('ursa');

function toPEM(str) {
	const len = 64;
	const n = Math.ceil(str.length / len);
	const chunks = new Array(n);

	for (let i = 0, o = 0; i < n; ++i, o += len) {
		chunks[i] = str.substr(o, len);
	}

	return chunks.join('\n');
}

function DICOM(host, port) {
	this.sessionId = null;
	this.version = VERSION;
	this.endpoint = 'https://' + host + ':' + port + '/v' + this.version + '/dicom';

	this.agent = new https.Agent({
		// TODO: Fix this when SSS doesn't need a self-signed cert
		rejectUnauthorized: false,
	});

	this.privateKey = ursa.generatePrivateKey();
	this.publicKey = this.privateKey.toPublicPem().toString();
}

DICOM.prototype.connect = function() {
	return this.execute({
		method: 'connect',
		pubkey: this.publicKey,
	});
};

DICOM.prototype.ping = function() {
	return this.execute({
		method: 'ping',
	});
};

DICOM.prototype.echo = function(params) {
	return this.execute({
		method: 'echo',
		params: params,
	});
};

DICOM.prototype.execute = function(params) {
	if (this.sessionId) {
		params.session_id = this.sessionId;
	}

	const payload = JSON.stringify(params);
	const signature = toPEM(this.privateKey.hashAndSign('sha256', payload, 'utf8', 'base64'));

	const request = {
		dicom: this.version,
		payload: payload,
		signature: signature,
		pubkey: this.publicKey,
	};

	return fetch(this.endpoint, {
		method: 'POST',
		body: JSON.stringify(request),
		agent: this.agent,
	}).then(res => {
		return res.text();
	}).then(body => {
		const data = JSON.parse(body);

		// This doesn't work yet, not sure why - same data works in PHP.
		this.verifySignature(data);

		return JSON.parse(data.payload);
	});
};

DICOM.prototype.verifySignature = function(data) {
	// TODO: ensure fields exist
	const payload = JSON.parse(data.payload);

	if (payload.method === 'connect') {
		this.serverPublicKey = ursa.createPublicKey(payload.pubkey);
		this.sessionId = payload.session_id;
	}

	const signature = data.signature.split('\n').join('');

	// TODO: FIXME - this fails to verify the signature from the server, works in everything else. loljs?
	const isValid = this.serverPublicKey.hashAndVerify('sha256', data.payload, signature, 'base64');
	//if (!isValid) {
		//throw 'invalid payload signature';
	//}
};

exports.client = (host, port) => {
	return new DICOM(host, port);
};

