import {
  Cipher,
  Constrained,
  Extension,
  Struct,
  TLSPlaintext,
  Version, Handshake
} from "../src/dep.ts";

/**
 * Represents a TLS 1.3 ClientHello message.
 *
 * This class constructs, parses, and manages the ClientHello message in the TLS handshake.
 */
export class ClientHello extends Struct {
  legacy_version: Version;
  random: Uint8Array;
  legacy_session: Legacy_session_id;
  cipher_suites: Cipher_suites;
  legacy_compression_methods: Legacy_compression_methods;
  extensions: Extensions;
  ext: Map<string, { pos: number; data: Uint8Array }>;

  /**
   * Parses a `ClientHello` message from a `Handshake` byte array.
   * @param {Uint8Array} handshake - The raw handshake message.
   * @returns {ClientHello} The parsed `ClientHello` instance.
   */
  static fromHandShake(handshake: Uint8Array): ClientHello;

  /**
   * Alias for `fromHandShake`.
   */
  static fromHandshake: typeof ClientHello.fromHandShake;

  /**
   * Parses a `ClientHello` from a raw `Uint8Array`.
   * @param {Uint8Array} array - The raw TLS message.
   * @returns {ClientHello} The parsed `ClientHello` instance.
   */
  static from(array: Uint8Array): ClientHello;

  /**
   * Constructs a new `ClientHello` message.
   *
   * @param {Uint8Array} [random] - A 32-byte random value.
   * @param {Legacy_session_id} [legacy_session] - The session ID.
   * @param {Cipher_suites} [cipher_suites] - The supported cipher suites.
   * @param {...Extensions[]} extensions - The optional extensions.
   */
  constructor(
    legacy_version: Version,
    random?: Uint8Array,
    legacy_session?: Legacy_session_id,
    cipher_suites?: Cipher_suites,
    ...extensions: Extensions[]
  );

  /**
   * Creates a `ClientHello` instance with a specific server name extension.
   *
   * @param {string} serverName - The server name to include in the extension.
   * @returns {ClientHello} A `ClientHello` with the server name extension.
   */
  static fromServerName(serverName: string): ClientHello;

  /**
   * Converts the `ClientHello` into a `Handshake` message.
   * @returns {Handshake} The handshake message.
   */
  get handshake(): Handshake;

  /**
   * Converts the `ClientHello` into a `TLSPlaintext` record.
   * @returns {TLSPlaintext} The TLS record.
   */
  get record(): TLSPlaintext;

  /**
   * Adds PSK binders to the ClientHello.
   *
   * @param {Uint8Array} binders - The PSK binders.
   * @returns {ClientHello} A new `ClientHello` with the binders added.
   */
  addBinders(binders: Uint8Array): ClientHello;

  /**
   * Gets the position of the PSK binder within the message.
   *
   * @returns {number} The position of the binder.
   */
  binderPos(): number;
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
