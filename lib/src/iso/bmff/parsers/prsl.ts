import type { Entity } from '../boxes/Entity.js';
import type { Fields } from '../boxes/Fields.js';
import type { PreselectionGroupBox } from '../boxes/PreselectionGroupBox.js';
import type { IsoView } from '../IsoView.js';

/**
 * Parse a PreselectionGroupBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed PreselectionGroupBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function prsl(view: IsoView): Fields<PreselectionGroupBox> {
	const { version, flags } = view.readFullBox();
	const groupId = view.readUint(4);
	const numEntitiesInGroup = view.readUint(4);
	const entities = view.readEntries<Entity>(numEntitiesInGroup, () => ({
		entityId: view.readUint(4),
	}));
	const preselectionTag = flags & 0x1000 ? view.readUtf8(-1) : undefined;
	const selectionPriority = flags & 0x2000 ? view.readUint(1) : undefined;
	const interleavingTag = flags & 0x4000 ? view.readUtf8(-1) : undefined;

	return {
		version,
		flags,
		groupId,
		numEntitiesInGroup,
		entities,
		preselectionTag,
		selectionPriority,
		interleavingTag,
	};
}
