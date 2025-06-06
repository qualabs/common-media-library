import { unescapeHtml } from '../utils/unescapeHtml.js';
import type { XmlNode } from './XmlNode.js';
import type { XmlParseOptions } from './XmlParseOptions.js';

/**
 * Parse XML into a JS object with no validation and some failure tolerance
 *
 * @param input - The input XML string
 * @param options - Optional parsing options
 * @returns The parsed XML
 *
 * @group XML
 *
 * @beta
 *
 * @example
 * {@includeCode ../../test/xml/parseXml.test.ts#example}
 */
export function parseXml(input: string, options: XmlParseOptions = {}): XmlNode {
	let pos = options.pos || 0;

	const length = input.length;
	const keepComments = !!options.keepComments;
	const keepWhitespace = !!options.keepWhitespace;

	const openBracket = '<';
	const openBracketCC = '<'.charCodeAt(0);
	const closeBracket = '>';
	const closeBracketCC = '>'.charCodeAt(0);
	const minusCC = '-'.charCodeAt(0);
	const slashCC = '/'.charCodeAt(0);
	const questionCC = '?'.charCodeAt(0);
	const exclamationCC = '!'.charCodeAt(0);
	const singleQuoteCC = "'".charCodeAt(0);
	const doubleQuoteCC = '"'.charCodeAt(0);
	const openCornerBracketCC = '['.charCodeAt(0);
	const closeCornerBracketCC = ']'.charCodeAt(0);
	const nameSpacer = '\r\n\t>/= ';

	function createTextNode(value: string, nodeName = '#text'): XmlNode {
		return {
			nodeName,
			nodeValue: value,
			attributes: {},
			childNodes: [],
		};
	}

	/**
	 * parsing a list of entries
	 */
	function parseChildren(tagName: string = ''): XmlNode[] {
		const children: any[] = [];
		while (input[pos]) {
			if (input.charCodeAt(pos) == openBracketCC) {
				if (input.charCodeAt(pos + 1) === slashCC) {
					const closeStart = pos + 2;
					pos = input.indexOf(closeBracket, pos);
					if (!input.startsWith(tagName, closeStart)) {
						const parsedText = input.substring(0, pos).split('\n');
						throw new Error(
							'Unexpected close tag\nLine: ' + (parsedText.length - 1) +
							'\nColumn: ' + (parsedText[parsedText.length - 1].length + 1) +
							'\nChar: ' + input[pos],
						);
					}

					if (pos + 1) {
						pos += 1;
					}

					return children;
				}
				else if (input.charCodeAt(pos + 1) === questionCC) {
					// xml declaration
					pos = input.indexOf(closeBracket, pos);
					pos++;
					continue;
				}
				else if (input.charCodeAt(pos + 1) === exclamationCC) {
					if (input.charCodeAt(pos + 2) == minusCC) {
						// comment support
						const startCommentPos = pos;
						while (pos !== -1 && !(input.charCodeAt(pos) === closeBracketCC && input.charCodeAt(pos - 1) == minusCC && input.charCodeAt(pos - 2) == minusCC && pos != -1)) {
							pos = input.indexOf(closeBracket, pos + 1);
						}
						if (pos === -1) {
							pos = length;
						}
						if (keepComments) {
							children.push(createTextNode(input.substring(startCommentPos, pos + 1), '#comment'));
						}
					}
					else if (
						input.charCodeAt(pos + 2) === openCornerBracketCC &&
						input.charCodeAt(pos + 8) === openCornerBracketCC &&
						input.startsWith('CDATA', pos + 3)
					) {
						// cdata
						const cdataEndIndex = input.indexOf(']]>', pos);
						if (cdataEndIndex == -1) {
							children.push(createTextNode(input.substr(pos + 9), '#cdata'));
							pos = length;
						}
						else {
							children.push(createTextNode(input.substring(pos + 9, cdataEndIndex), '#cdata'));
							pos = cdataEndIndex + 3;
						}
						continue;
					}
					else {
						// doctypesupport
						const startDoctype = pos + 1;
						pos += 2;
						let encapsuled = false;
						while ((input.charCodeAt(pos) !== closeBracketCC || encapsuled === true) && input[pos]) {
							if (input.charCodeAt(pos) === openCornerBracketCC) {
								encapsuled = true;
							}
							else if (encapsuled === true && input.charCodeAt(pos) === closeCornerBracketCC) {
								encapsuled = false;
							}
							pos++;
						}
						children.push(createTextNode(input.substring(startDoctype, pos), '#doctype'));
					}

					pos++;
					continue;
				}

				const node = parseNode();
				children.push(node);
			}
			else {
				const text = parseText();
				if (keepWhitespace) {
					if (text.length > 0) {
						children.push(createTextNode(text));
					}
				}
				else {
					const trimmed = text.trim();
					if (trimmed.length > 0) {
						children.push(createTextNode(trimmed));
					}
				}
				pos++;
			}
		}
		return children;
	}

	/**
	 * returns the text outside of texts until the first '&lt;'
	 */
	function parseText(): string {
		const start = pos;
		pos = input.indexOf(openBracket, pos) - 1;
		if (pos === -2) {
			pos = length;
		}

		return unescapeHtml(input.slice(start, pos + 1));
	}

	/**
	 * returns text until the first nonAlphabetic letter
	 */
	function parseName(): string {
		const start = pos;
		while (nameSpacer.indexOf(input[pos]) === -1 && input[pos]) {
			pos++;
		}
		return input.slice(start, pos);
	}

	/**
	 * parses the attributes of a node
	 */
	function parseAttributes(): Record<string, string> {
		const attributes: Record<string, string> = {};

		// parsing attributes
		while (input.charCodeAt(pos) !== closeBracketCC && input[pos]) {
			const c = input.charCodeAt(pos);
			if ((c > 64 && c < 91) || (c > 96 && c < 123)) {
				const name = parseName();
				let value: string = '';
				// search beginning of the string
				let code = input.charCodeAt(pos);
				while (code !== singleQuoteCC && code !== doubleQuoteCC) {
					pos++;
					code = input.charCodeAt(pos);
				}

				if (code === singleQuoteCC || code === doubleQuoteCC) {
					value = parseString();
					if (pos === -1) {
						throw new Error('Missing closing quote');
					}
				}
				else {
					pos--;
				}

				attributes[name] = unescapeHtml(value);
			}
			pos++;
		}

		return attributes;
	}

	/**
	 * parses a node
	 */
	function parseNode(): XmlNode {
		pos++;
		const nodeName = parseName();
		let localName = nodeName;
		let prefix = null;

		const nsIndex = nodeName.indexOf(':');
		if (nsIndex !== -1) {
			prefix = nodeName.slice(0, nsIndex);
			localName = nodeName.slice(nsIndex + 1);
		}

		const attributes = parseAttributes();

		let childNodes: any[] = [];

		// optional parsing of children
		const prev = input.charCodeAt(pos - 1);
		pos++;

		if (prev !== slashCC) {
			childNodes = parseChildren(nodeName);
		}

		return {
			nodeName,
			nodeValue: null,
			attributes,
			childNodes,
			prefix,
			localName,
		};
	}

	/**
	 * is parsing a string, that starts with a char and with the same usually ' or "
	 */
	function parseString(): string {
		const startChar = input[pos];
		const startpos = pos + 1;
		pos = input.indexOf(startChar, startpos);
		return input.slice(startpos, pos);
	}

	return {
		nodeName: '#document',
		nodeValue: null,
		childNodes: parseChildren(''),
		attributes: {},
	};
}
