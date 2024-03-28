import { PathwayClone } from './PathwayClone';

export type SteeringManifest = {
  VERSION: 1;
  TTL: 300;
  'RELOAD-URI'?: string;
  'PATHWAY-PRIORITY': string[];
  'PATHWAY-CLONES'?: PathwayClone[];
};
