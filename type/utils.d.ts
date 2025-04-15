/**
 * Parses items from a Uint8Array and stores them in a Set, Map, or Array.
 * @param {Uint8Array} copy - The Uint8Array to parse.
 * @param {number} start - The starting offset for parsing.
 * @param {number} lengthOf - The total length to parse.
 * @param {any} Fn - The constructor function for the items to parse, with a static `from` method.
 * @param {object} [option] - Optional parameters.
 * @param {function} [option.parser] - An optional parser function to process each item.
 * @param {Set<any> | Map<any, any> | any[]} [option.store=new Set()] - The store to hold parsed items. Defaults to a new Set.
 * @param {function} [option.storeset] - A function to store items in a Map. Defaults to setting key-value pairs.
 * @returns {Set<any> | Map<any, any> | any[]} - The store containing parsed items.
 * @throws {RangeError} - If the specified length exceeds available data.
 * @throws {TypeError} - If the store is not an instance of Set, Map, or Array.
 */
export declare function parseItems(
   copy: Uint8Array,
   start: number,
   lengthOf: number,
   Fn: any,
   option?: {
     parser?: (item: any) => void;
     store?: Set<any> | Map<any, any> | any[];
     storeset?: (store: Map<any, any>, data: any) => void;
   }
 ): Set<any> | Map<any, any> | any[];