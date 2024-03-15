export async function callContentSteeringServer(
	serverURI: string | null
): Promise<string> {
	if (!serverURI) {
		throw new Error('Server URI is null');
	}
	const response = await fetch(serverURI);
	if (!response.ok) {
		throw new Error(`HTTP error! status: ${response.status}`);
	}
	return response.text();
}