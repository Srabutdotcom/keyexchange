import {
   Cipher,
   Constrained,
   Extension,
   ExtensionType,
   Struct,
   Uint16,
   Uint8,
   Version,
   TLSPlaintext
} from "../src/dep.ts";
import {
   KeyShareServerHello,
   NamedGroup,
   Selected_version,
   SupportedVersions,
} from "../src/dep.ts";

/**
 * Represents the `ServerHello` structure in TLS.
 */
export class ServerHello extends Struct {
   /** Legacy version of the protocol. */
   legacy_version: Version;

   /** Random value used in the handshake. */
   random: Uint8Array;

   /** Echoed session ID from the client. */
   legacy_session_id_echo: Legacy_session_id;

   /** Cipher suite selected for the session. */
   cipher_suite: Cipher;

   /** Legacy compression method (always 0). */
   legacy_compression_method: Uint8;

   /** List of extensions included in the `ServerHello`. */
   extensions: Extensions;

   /** Parsed extensions as a key-value map. */
   ext: Record<string, any>;

   /** Static factory to create `ServerHello` from `ClientHello`. */
   static fromClient_hello(clientHello: any): ServerHello;

   /**
    * Parses a `ServerHello` instance from a byte array.
    * @param {Uint8Array} array - The byte array to parse.
    * @returns {ServerHello} A `ServerHello` instance.
    */
   static from(array: Uint8Array): ServerHello;

   /**
    * Constructor for `ServerHello`.
    * @param {Uint8Array} random - Random value (32 bytes).
    * @param {Legacy_session_id} legacy_session_id_echo - Session ID echo.
    * @param {Cipher} cipher_suite - Cipher suite.
    * @param {...Extension[]} extensions - Extensions included in `ServerHello`.
    */
   constructor(
      random?: Uint8Array,
      legacy_session_id_echo?: Legacy_session_id,
      cipher_suite?: Cipher,
      ...extensions: Extension[]
   );
   /**
   * Converts the current instance into a TLSPlaintext record.
   * 
   * @returns {TLSPlaintext} A `TLSPlaintext` object representing the current instance.
   * The `ContentType` is set to `HANDSHAKE`, and the data is encoded as a plaintext record.
   */
   toRecord(): TLSPlaintext;
}

/**
 * Represents the `Extensions` structure, a constrained list of extensions.
 */
declare class Extensions extends Constrained {
   /** Array of extensions. */
   extensions: Extension[];

   /**
    * Creates an `Extensions` instance from individual extensions.
    * @param {...Extension[]} extensions - The extensions to include.
    * @returns {Extensions} A new `Extensions` instance.
    */
   static fromExtension(...extensions: Extension[]): Extensions;

   /**
    * Parses an `Extensions` instance from a byte array.
    * @param {Uint8Array} array - The byte array to parse.
    * @returns {Extensions} An `Extensions` instance.
    */
   static from(array: Uint8Array): Extensions;

   /**
    * Constructor for `Extensions`.
    * @param {...Extension[]} extensions - The extensions to include.
    */
   constructor(...extensions: Extension[]);
}

/**
 * Represents the legacy session ID structure.
 */
declare class Legacy_session_id extends Constrained {
   /** Opaque session ID value. */
   opaque: Uint8Array;

   /**
    * Parses a `Legacy_session_id` instance from a byte array.
    * @param {Uint8Array} array - The byte array to parse.
    * @returns {Legacy_session_id} A `Legacy_session_id` instance.
    */
   static from(array: Uint8Array): Legacy_session_id;

   /**
    * Constructor for `Legacy_session_id`.
    * @param {Uint8Array} opaque - The session ID (0-32 bytes).
    */
   constructor(opaque?: Uint8Array);
}

/**
 * Parses and modifies an extension based on its type.
 * @param {Extension} extension - The extension to parse.
 */
declare function parseExtension(extension: Extension): void;

/**
 * Constructs a `ServerHello` instance from a `ClientHello`.
 * @param {any} clientHello - The `ClientHello` structure.
 * @returns {ServerHello} A `ServerHello` instance.
 */
declare function fromClient_hello(clientHello: any): ServerHello;
