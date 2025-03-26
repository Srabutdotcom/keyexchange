import { Cipher, Extension, NamedGroup, Version } from "../src/dep.ts";
import { ClientHello } from "../src/mod.ts";

/**
 * Represents a TLS ServerHello message as a Uint8Array.
 */
export class ServerHello extends Uint8Array {
  /** @type {Version} TLS version (legacy_version = 0x0303 for TLS 1.2) */
  #legacy_version: Version;
  /** @type {Uint8Array} Random value (32 bytes) */
  #random: Uint8Array;
  /** @type {Uint8Array} Legacy session ID echoed from ClientHello */
  #legacy_session_id_echo: Uint8Array;
  /** @type {Cipher} Cipher suite selected */
  #cipher_suite: Cipher;
  /** @type {Uint8Array} Legacy compression method */
  #legacy_compression_method: Uint8Array;
  /** @type {Map<number, Extension>} Extensions in ServerHello */
  #extensions: Map<number, Extension>;

  /**
   * Creates a new ServerHello instance.
   * @param {...any} args - Arguments for the ServerHello constructor.
   * @returns {ServerHello}
   */
  static create(...args: any[]): ServerHello;
  
  /**
   * Alias for ServerHello.create.
   */
  static from: typeof ServerHello.create;

  /**
   * Constructs a ServerHello instance.
   * @param {...any} args - Arguments for the ServerHello constructor.
   */
  constructor(...args: any[]);

  /**
   * Gets the TLS version.
   * @returns {Version}
   */
  get version(): Version;

  /**
   * Gets the random bytes.
   * @returns {Uint8Array}
   */
  get random(): Uint8Array;

  /**
   * Gets the legacy session ID.
   * @returns {Uint8Array}
   */
  get legacy_session_id(): Uint8Array;

  /**
   * Gets the cipher suite.
   * @returns {Cipher}
   */
  get cipher(): Cipher;

  /**
   * Gets the legacy compression methods.
   * @returns {Uint8Array}
   */
  get legacy_compression_methods(): Uint8Array;

  /**
   * Gets the extensions in the ServerHello message.
   * @returns {Map<number, Extension>}
   */
  get extensions(): Map<number, Extension>;

  /**
   * Gets the handshake message.
   * @returns {Uint8Array}
   */
  get handshake(): Uint8Array;

  /**
   * Gets the TLS record for the ServerHello message.
   * @returns {Uint8Array}
   */
  get record(): Uint8Array;

  /**
   * Checks if the ServerHello message is a HelloRetryRequest (HRR).
   * @returns {boolean}
   */
  get isHRR(): boolean;

  /**
   * Sets the supported groups in the ClientHello message.
   * @param {NamedGroup} group - The supported groups.
   */
  set group(group: NamedGroup);

  /**
   * Gets the supported groups in the ClientHello message.
   * @returns {NamedGroup}
   */
  get group(): NamedGroup;
}




