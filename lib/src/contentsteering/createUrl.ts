export function createUrl(
	uri: string,
	pathway?: string,
	throughput?: string
): string {
	if (!pathway && !throughput) {
		return uri;
	}

	const url = `${uri}&${pathway}&${throughput}`;

	return url;
}
