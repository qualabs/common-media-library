const manifestUrl =
	'https://fastly.content-steering.com/bbb_hls/master_steering_fastly_https.m3u8thisIsAWrongUri';

async function getManifest(url: string): Promise<string> {
	const response = await fetch(url);
	if (!response.ok) {
		throw new Error(`HTTP error! status: ${response.status}`);
	}
	return response.text();
}

async function parseContentSteeringURI(): Promise<string | null> {
	try {
		const manifest = await getManifest(manifestUrl);
		const lines = manifest.split(/\r?\n/);
		const steeringLine = lines.find((line) =>
			line.startsWith('#EXT-X-CONTENT-STEERING:')
		);
		const match = steeringLine?.match(/SERVER-URI="([^"]+)"/);
		return match ? match[1] : null;
	} 
	catch (error) {
		console.error('Failed to load manifest:', error);
		return null;
	}
}

interface ContentSteeringServerResponse {
	status: number;
	data: string;
	headers: Record<string, string>;
	url: string;
}

async function callContentSteeringServer(
	serverURI: string | null
): Promise<ContentSteeringServerResponse> {
	if (!serverURI) {
		throw new Error('Server URI is null');
	}

	const response = await fetch(serverURI);
	const data = await response.text();

	const headers: Record<string, string> = {};
	response.headers.forEach((value, key) => {
		headers[key] = value;
	});

	const ContentSteeringServerResponse: ContentSteeringServerResponse = {
		status: response.status,
		data: data,
		headers: headers,
		url: response.url,
	};

	return ContentSteeringServerResponse;
}

async function main() {
	try {
		const serverURI = await parseContentSteeringURI();
		if (serverURI) {
			const response = await callContentSteeringServer(serverURI);
			console.log('Content Steering Server Response:', response);
		} 
		else {
			console.log('No content steering URI found in the manifest.');
		}
	} 
	catch (error) {
		console.error('Error:', error);
	}
}

main();
