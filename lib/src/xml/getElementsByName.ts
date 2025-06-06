import type { XmlNode } from './XmlNode.js';

/**
 * Recursively finds all elements by name within an XML structure.
 *
 * @param node - The current XML node to search within.
 * @param name - The name of the target nodes to find.
 * @param found - An array to collect matching nodes.
 * @returns An array of all matching XmlNodes.
 *
 * @group XML
 *
 * @beta
 *
 */
export function getElementsByName(node: XmlNode, name: string, found: XmlNode[] = []): XmlNode[] {
	if (node.nodeName === name) {
		found.push(node);
	}

	if (node.childNodes) {
		for (const child of node.childNodes) {
			getElementsByName(child, name, found);
		}
	}

	return found;
}
