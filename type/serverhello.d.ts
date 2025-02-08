import {
   Cipher,
   Version,
   ExtensionType
} from "../src/dep.ts";

/**
 * Represents a ServerHello message.
 */
export class ServerHello extends Uint8Array {
   #legacy_version: Version | null ;
   #random: Uint8Array | null ;
   #legacy_session_id_echo: Uint8Array | null ;
   #cipher_suite: Cipher | null ;
   #legacy_compression_method: Uint8Array | null ;
   #extensions: Map<ExtensionType, any> | null ;
 
   /**
    * Creates a new ServerHello instance.
    * @static
    * @param {...any[]} args - The arguments to create the ServerHello.
    *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
    *   - Otherwise, the arguments are treated as byte values.
    * @returns {ServerHello} A new ServerHello instance.
    */
   static create(...args: any[]): ServerHello;
 
   /**
    * Creates a new ServerHello instance (alias for `create`).
    * @static
    * @param {...any[]} args - The arguments to create the ServerHello.
    *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
    *   - Otherwise, the arguments are treated as byte values.
    * @returns {ServerHello} A new ServerHello instance.
    */
   static from(...args: any[]): ServerHello;
 
   /**
    * Constructs a new ServerHello instance.
    * @param {...any[]} args - The arguments to create the ServerHello.
    *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
    *   - Otherwise, the arguments are treated as byte values.
    */
   constructor(...args: any[]);
 
   /**
    * The legacy TLS version (0x0303 for TLS 1.2).
    * @readonly
    * @type {Version}
    */
   get version(): Version;
 
   /**
    * The server random value.
    * @readonly
    * @type {Uint8Array}
    */
   get random(): Uint8Array;
 
   /**
    * The echoed legacy session ID.
    * @readonly
    * @type {Uint8Array}
    */
   get legacy_session_id(): Uint8Array;
 
   /**
    * The chosen cipher suite.
    * @readonly
    * @type {Cipher}
    */
   get cipher(): Cipher;
 
   /**
    * The legacy compression method (should be zero in TLS 1.3).
    * @readonly
    * @type {Uint8Array}
    */
   get legacy_compression_methods(): Uint8Array;
 
   /**
    * The TLS extensions.
    * @readonly
    * @type {Map<ExtensionType, any>}
    */
   get extensions(): Map<ExtensionType, any>;
 }





