// Function to parse the M3U8 manifest and extract the content steering server URI
export async function parseContentSteeringURI(manifest: string) {
	const lines = manifest.split(/\r?\n/);
	const steeringLine = lines.find((line) =>
		line.startsWith('#EXT-X-CONTENT-STEERING:')
	);
	if (steeringLine) {
		const match = steeringLine.match(/SERVER-URI='([^']+)'/);
		return match ? match[1] : null;
	}
	return null;
}
