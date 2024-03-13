import * as https from 'https';

// Function to call the content steering server
export async function callContentSteeringServer(serverURI: string | null) {
	if (!serverURI) {
		throw new Error('Server URI is null');
	}

	return new Promise((resolve, reject) => {
		https
			.get(serverURI, (res) => {
				let data = '';
				res.on('data', (chunk) => {
					data += chunk;
				});
				res.on('end', () => {
					resolve(data);
				});
			})
			.on('error', (err) => {
				reject(err);
			});
	});
}
