interface ContentSteeringServerResponse {
	status: number;
	data: JSON;
	headers: Record<string, string>;
	url: string;
}

export async function callContentSteeringServer(
	serverURI: string | null,
	onSuccess: (response: ContentSteeringServerResponse) => void,
	onError: (response: ContentSteeringServerResponse) => void,
	onTimeout: (serverURI: string) => void,
	timeoutMilliseconds: number = 5000
): Promise<void> {
	if (!serverURI) {
		throw new Error('Server URI is null');
	}

	try {
		const response = await fetch(serverURI, {
			signal: AbortSignal.timeout(timeoutMilliseconds),
		});
		if (!response.ok) {
			throw new Error(`HTTP error! status: ${response.status}`);
		}
		const data = await response.json();

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
		if (error instanceof DOMException) {
			if (error.name === 'AbortError') {
				console.log('The fetch request was aborted.');
			} 
			else if (error.name === 'TimeoutError') {
				onTimeout(serverURI);
			} 
			else {
				console.log('A DOMException occurred:', error.message);
			}
		} 
		else if (error instanceof Error) {
			console.log('There was an error:', error.message);
		} 
		else {
			console.log('An unexpected error occurred:', error);
		}
	}
    
}
