import {
  Cipher,
  Constrained,
  Extension,
  Struct,
  Version,
} from "../src/dep.ts";

/**
 * Represents a ClientHello message in TLS.
 */
export class ClientHello extends Struct {
  /**
   * Legacy protocol version.
   */
  legacy_version: Version;

  /**
   * Random bytes used in the handshake.
   */
  random: Uint8Array;

  /**
   * Legacy session ID.
   */
  legacy_session: Legacy_session_id;

  /**
   * Supported cipher suites.
   */
  cipher_suites: Cipher_suites;

  /**
   * Legacy compression methods.
   */
  legacy_compression_methods: Legacy_compression_methods;

  /**
   * TLS extensions included in the ClientHello.
   */
  extensions: Extension[];

  /** Parsed extensions as key-value pairs. The key represents the extension type, and the value represents the parsed Extension. */
  ext: Record<string, Extension>;

  /**
   * Creates a ClientHello instance from a Uint8Array.
   * @param {Uint8Array} array - The byte array representing the ClientHello message.
   * @returns {ClientHello} - A new ClientHello instance.
   */
  static from(array: Uint8Array): ClientHello;

  /**
   * Constructs a new ClientHello message.
   * @param {Uint8Array} [random] - Random bytes (default: 32 random bytes).
   * @param {Legacy_session_id} [legacy_session] - Legacy session ID.
   * @param {Cipher_suites} [cipher_suites] - Supported cipher suites.
   * @param {Extension[]} [extensions] - TLS extensions.
   */
  constructor(
    random?: Uint8Array,
    legacy_session?: Legacy_session_id,
    cipher_suites?: Cipher_suites,
    ...extensions: Extension[]
  );

  /**
   * Creates a ClientHello message for a specific server name.
   * @param {string} serverName - The server name.
   * @returns {ClientHello} - A new ClientHello instance configured for the server name.
   */
  static fromServerName(serverName: string): ClientHello;
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
