/**
 * A collection of tools for working with DRM.
 *
 * @packageDocumentation
 *
 * @beta
 */

// common utils
export * from './drm/cenc/findCencContentProtection.js';
export * from './drm/cenc/getLicenseServerUrlFromContentProtection.js';
export * from './drm/cenc/getPsshData.js';
export * from './drm/cenc/getPsshForKeySystem.js';
export * from './drm/cenc/parseInitDataFromContentProtection.js';
export * from './drm/cenc/parsePsshList.js';

// key system utils
export * from './drm/keysystem/createMediaKeySystemConfiguration.js';
export * from './drm/keysystem/getKeySystemAccess.js';
export * from './drm/keysystem/getLegacyKeySystemAccess.js';
export * from './drm/keysystem/getSupportedKeySystemConfiguration.js';

// fairplay utilities
export * from './drm/fairplay/concatInitDataIdAndCertificate.js';
export * from './drm/fairplay/decodeFairPlayLicense.js';
export * from './drm/fairplay/extractContentId.js';
export * from './drm/fairplay/getId.js';
export * from './drm/fairplay/getLicenseServerUrl.js';

// playready utilities
export * from './drm/playready/getLicenseRequestFromMessage.js';
export * from './drm/playready/getRequestHeadersFromMessage.js';
export * from './drm/playready/toBigEndianKeyId.js';

// drm types
export type { ContentProtection } from './drm/common/ContentProtection.js';
export type { LicenseRequest } from './drm/common/LicenseRequest.js';
export type { MediaKeySystemAccessRequest } from './drm/common/MediaKeySystemAccessRequest.js';

// drm constants
export * from './drm/common/CBCS.js';
export * from './drm/common/CENC.js';
export * from './drm/common/CHALLENGE.js';
export * from './drm/common/CLEAR_KEY_SYSTEM.js';
export * from './drm/common/CLEAR_KEY_UUID.js';
export * from './drm/common/CONTENT_TYPE.js';
export * from './drm/common/EncryptionScheme.js';
export * from './drm/common/EXPIRED.js';
export * from './drm/common/FAIRPLAY_KEY_SYSTEM.js';
export * from './drm/common/FAIRPLAY_UUID.js';
export * from './drm/common/HTTP_HEADERS.js';
export * from './drm/common/HW_SECURE_ALL.js';
export * from './drm/common/HW_SECURE_CRYPTO.js';
export * from './drm/common/HW_SECURE_DECODE.js';
export * from './drm/common/INDIVIDUALIZATION_REQUEST.js';
export * from './drm/common/InitializationDataType.js';
export * from './drm/common/INTERNAL_ERROR.js';
export * from './drm/common/KEYIDS.js';
export * from './drm/common/LICENSE_ACQUISITION.js';
export * from './drm/common/LICENSE_RELEASE.js';
export * from './drm/common/LICENSE_RENEWAL.js';
export * from './drm/common/LICENSE_REQUEST.js';
export * from './drm/common/MediaKeyMessageType.js';
export * from './drm/common/MediaKeyStatus.js';
export * from './drm/common/MP4_PROTECTION_SCHEME.js';
export * from './drm/common/OUTPUT_DOWNSCALED.js';
export * from './drm/common/OUTPUT_RESTRICTED.js';
export * from './drm/common/PLAYREADY_KEY_MESSAGE.js';
export * from './drm/common/PLAYREADY_KEY_SYSTEM.js';
export * from './drm/common/PLAYREADY_RECOMMENDATION_KEY_SYSTEM.js';
export * from './drm/common/PLAYREADY_UUID.js';
export * from './drm/common/RELEASED.js';
export * from './drm/common/STATUS_PENDING.js';
export * from './drm/common/SW_SECURE_CRYPTO.js';
export * from './drm/common/SW_SECURE_DECODE.js';
export * from './drm/common/TEXT_XML_UTF8.js';
export * from './drm/common/USABLE.js';
export * from './drm/common/W3C_CLEAR_KEY_UUID.js';
export * from './drm/common/WEBM.js';
export * from './drm/common/WIDEVINE_KEY_SYSTEM.js';
export * from './drm/common/WIDEVINE_UUID.js';
export * from './drm/common/WidevineRobustness.js';
