// Function to parse the M3U8 manifest and extract the content steering server URI
export async function parseContentSteeringURI(manifest: string): Promise<string | null> {
	try {
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
