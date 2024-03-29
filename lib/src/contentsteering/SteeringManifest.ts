export class ContentSteeringResponse {
	version: number | null;
	ttl: number;
	reloadUri: string | null;
	pathwayPriority: string[];
	pathwayClones: any;

	constructor(response?: any) {
		this.version = response?.VERSION ?? null;
		this.ttl = response?.TTL ?? 300;
		this.reloadUri = response?.['RELOAD-URI'] ?? null;
		this.pathwayPriority = response?.['PATHWAY-PRIORITY'] ?? null;
		this.pathwayClones = response?.['PATHWAY-CLONES'] ?? [];
	}
}
