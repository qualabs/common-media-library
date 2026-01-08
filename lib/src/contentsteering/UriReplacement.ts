export type UriReplacement = {
  HOST?: string;
  PARAMS?: { [queryParameter: string]: string };
  'PER-VARIANT-URIS'?: { [stableVariantId: string]: string };
  'PER-RENDITION-URIS'?: { [stableRenditionId: string]: string };
};
