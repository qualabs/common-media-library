interface ContentSteeringServerResponse {
	status: number;
	data: string;
	headers: Record<string, string>;
	url: string;
}

export async function callContentSteeringServer(
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
