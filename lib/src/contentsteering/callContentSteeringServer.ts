interface ContentSteeringServerResponse {
	status: number;
	data: string;
	headers: Record<string, string>;
	url: string;
}

export async function callContentSteeringServer(
	serverURI: string | null,
	onSuccess: (response: ContentSteeringServerResponse) => void,
	onError: (response: ContentSteeringServerResponse) => void,
	onTimeout: (serverURI: string) => void,
	timeout: number = 5000
): Promise<void> {
	if (!serverURI) {
		throw new Error('Server URI is null');
	}

	try {
		const response = await fetch(serverURI, {
			signal: AbortSignal.timeout(timeout),
		});
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

		if (response.status >= 200 && response.status < 300) {
			onSuccess(ContentSteeringServerResponse);
		}
		else if (response.status >= 400 && response.status < 600) {
			onError(ContentSteeringServerResponse);
		}
	}
	catch (error: any) {
		if (error instanceof DOMException && error.name === 'TimeoutError') {
			onTimeout(serverURI);
		}
	}
}
