import {
  Cipher,
  Constrained,
  Extension,
  Version, 
  ExtensionType
} from "../src/dep.ts";

/**
 * Represents a TLS 1.3 ClientHello message.
 *
 * This class constructs, parses, and manages the ClientHello message in the TLS handshake.
 */
/**
 * Represents a TLS ClientHello message.
 * @class
 * @extends Uint8Array
 */
export class ClientHello extends Uint8Array {
  #version: Version | null 
  #random: Uint8Array | null 
  #legacy_session_id: Uint8Array | null 
  #ciphers: Cipher_suites | null ;
  #legacy_compression_methods: Uint8Array | null ;
  #extensions: Map<ExtensionType, any> | null ; // Use appropriate type for extension data

  /**
   * Create a new ClientHello from serverNames
   * @param {...string[]} serverNames 
   */
  static build(...serverNames: string[]): ClientHello;
  /**
   * Creates a new ClientHello instance.
   * @static
   * @param {...any[]} args - The arguments to create the ClientHello.
   *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
   *   - Otherwise, the arguments are treated as byte values.
   * @returns {ClientHello} A new ClientHello instance.
   */
  static create(...args: any[]): ClientHello;

  /**
   * Creates a new ClientHello instance (alias for `create`).
   * @static
   * @param {...any[]} args - The arguments to create the ClientHello.
   *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
   *   - Otherwise, the arguments are treated as byte values.
   * @returns {ClientHello} A new ClientHello instance.
   */
  static from(...args: any[]): ClientHello;


  /**
   * Constructs a new ClientHello instance.
   * @param {...(number | Uint8Array)} args - The arguments to create the ClientHello.
   *   - If a single Uint8Array is provided, it will be sanitized and used to create the new instance.
   *   - Otherwise, the arguments are treated as byte values.
   */
  constructor(...args: (number | Uint8Array)[]);

  /**
   * The TLS version.
   * @readonly
   * @type {Version}
   */
  get version(): Version;

  /**
   * The client random value.
   * @readonly
   * @type {Uint8Array}
   */
  get random(): Uint8Array;

  /**
   * The legacy session ID.
   * @readonly
   * @type {Uint8Array}
   */
  get legacy_session_id(): Uint8Array;

  /**
   * The cipher suites.
   * @readonly
   * @type {Cipher_suites}
   */
  get ciphers(): Cipher_suites;

  /**
   * The legacy compression methods (must be a single byte set to zero in TLS 1.3).
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

  /**
   * Adds PSK binders to the ClientHello extensions.
   * @param {Uint8Array} binders - The PSK binders to add.
   * @returns {ClientHello} A new ClientHello instance with the added binders.
   */
  addBinders(binders: Uint8Array): ClientHello;

  /**
   * Gets the position of the PSK binders in the ClientHello message.
   * @returns {number} The position of the PSK binders.
   */
  binderPos(): number;
  
  /**
   * Handshake of ClientHello or ClientHello Message
   * @readonly
   * @type {Uint8Array}
   */
  get handshake(): Uint8Array;
  
  /**
   * Record or TLSPlaintext of ClientHello Message 
   * @readonly
   * @type {Uint8Array}
   */
  get record(): Uint8Array;
}

/**
 * Represents the cipher suites in a ClientHello message.
 */
export class Cipher_suites extends Constrained {
  /**
   * List of supported cipher suites.
   */
  ciphers: Cipher[];

  /**
   * Creates a Cipher_suites instance from a Uint8Array.
   * @param {Uint8Array} array - The byte array containing the cipher suites.
   * @returns {Cipher_suites} - A new Cipher_suites instance.
   */
  static from(array: Uint8Array): Cipher_suites;

  /**
   * Constructs a new Cipher_suites instance.
   * @param {...Cipher} ciphers - The list of supported cipher suites.
   */
  constructor(...ciphers: Cipher[]);
}

/**
 * Represents extensions in a ClientHello message.
 */
declare class Extensions extends Constrained {
  /**
   * List of extensions in the ClientHello message.
   */
  extensions: Extension[];

  /**
   * Creates an Extensions instance from a list of Extension objects.
   * @param {...Extension} extensions - The list of extensions.
   * @returns {Extensions} - A new Extensions instance.
   */
  static fromExtension(...extensions: Extension[]): Extensions;

  /**
   * Creates an Extensions instance from a Uint8Array.
   * @param {Uint8Array} array - The byte array containing the extensions.
   * @returns {Extensions} - A new Extensions instance.
   */
  static from(array: Uint8Array): Extensions;
}

/**
 * Represents the legacy session ID in a ClientHello message.
 */
declare class Legacy_session_id extends Constrained {
  /**
   * Opaque session ID data.
   */
  opaque: Uint8Array;

  /**
   * Creates a Legacy_session_id instance from a Uint8Array.
   * @param {Uint8Array} array - The byte array containing the session ID.
   * @returns {Legacy_session_id} - A new Legacy_session_id instance.
   */
  static from(array: Uint8Array): Legacy_session_id;

  /**
   * Constructs a new Legacy_session_id instance.
   * @param {Uint8Array} [opaque] - The opaque session ID data (default: empty).
   */
  constructor(opaque?: Uint8Array);
}

/**
 * Represents legacy compression methods in a ClientHello message.
 */
declare class Legacy_compression_methods extends Constrained {
  /**
   * Opaque compression method data.
   */
  opaque: Uint8Array;

  /**
   * Creates a Legacy_compression_methods instance from a Uint8Array.
   * @param {Uint8Array} array - The byte array containing compression methods.
   * @returns {Legacy_compression_methods} - A new Legacy_compression_methods instance.
   */
  static from(array: Uint8Array): Legacy_compression_methods;

  /**
   * Constructs a new Legacy_compression_methods instance.
   * @param {Uint8Array} [opaque] - The opaque compression method data (default: [0]).
   */
  constructor(opaque?: Uint8Array);
}
