import {
  Cipher,
  Extension,
  NamedGroup,
  Version,
} from "../src/dep.ts";

/**
 * Represents a TLS ClientHello message as a Uint8Array.
 */
export class ClientHello extends Uint8Array {
  /** @#*/
  #version: Version;
  /** @#*/
  #random: Uint8Array;
  /** @#*/
  #legacy_session_id: Uint8Array & { end?: number };
  /** @#*/
  #ciphers: Cipher[] & { end?: number };
  /** @#*/
  #legacy_compression_methods: Uint8Array & { end?: number };
  /** @#*/
  #extensions: Map<number, Extension>;
  /** @#*/
  #groups: any;

  /**
   * Creates a new ClientHello instance.
   * @param {...any} args - Arguments to initialize the instance.
   * @returns {ClientHello}
   */
  static create(...args: any[]): ClientHello;
  static from: typeof ClientHello.create;

  /**
   * @param {...any} args - Arguments to initialize the instance.
   */
  constructor(...args: any[]);

  /**
   * Gets the TLS version from the ClientHello message.
   * @returns {Version}
   */
  get version(): Version;

  /**
   * Gets the random bytes from the ClientHello message.
   * @returns {Uint8Array}
   */
  get random(): Uint8Array;

  /**
   * Gets the legacy session ID from the ClientHello message.
   * @returns {Uint8Array & { end?: number }}
   */
  get legacy_session_id(): Uint8Array & { end?: number };

  /**
   * Gets the cipher suites offered in the ClientHello message.
   * @returns {Cipher[] & { end?: number }}
   */
  get ciphers(): Cipher[] & { end?: number };

  /**
   * Gets the legacy compression methods (must contain only `0`).
   * @returns {Uint8Array & { end?: number }}
   */
  get legacy_compression_methods(): Uint8Array & { end?: number };

  /**
   * Gets the extensions included in the ClientHello message.
   * @returns {Map<number, Extension>}
   */
  get extensions(): Map<number, Extension>;

  /**
   * Adds binders to the ClientHello message.
   * @param {Uint8Array} binders - The binders to add.
   * @returns {ClientHello}
   */
  addBinders(binders: Uint8Array): ClientHello;

  /**
   * Gets the position of the binder in the pre-shared key extension.
   * @returns {number}
   */
  binderPos(): number;

  /**
   * Gets the handshake message as a Uint8Array.
   * @returns {Uint8Array}
   */
  get handshake(): Uint8Array;

  /**
   * Gets the full TLS record for the ClientHello message.
   * @returns {Uint8Array}
   */
  get record(): Uint8Array;

  /**
   * Sets the supported groups in the ClientHello message.
   * @param {NamedGroup} groups - The supported groups.
   */
  set groups(groups: NamedGroup);

  /**
   * Gets the supported groups in the ClientHello message.
   * @returns {Map}
   */
  get groups(): Map<NamedGroup, NamedGroup>;
}

/**
 * Creates a `ClientHelloForm` instance for the given server names.
 * @param {string[]} serverNames - The list of server names.
 * @returns {ClientHelloForm} The ClientHelloForm instance.
 */
export function clientHelloForm(...serverNames: string[]): ClientHelloForm;

/**
 * Represents a TLS 1.3 ClientHello message builder.
 */
declare class ClientHelloForm {
  #version: Uint8Array;
  #random: Uint8Array;
  #sessionId: Uint8Array;
  #ciphers: Uint8Array;
  #compression: Uint8Array;
  #extensions: Map<number, Uint8Array>;
  #groups: Map<number, NamedGroup>;

  /**
   * Creates an instance of ClientHelloForm.
   * @param {string[]} serverNames - The list of server names.
   */
  constructor(...serverNames: string[]);

  /**
   * Builds the ClientHello message.
   * @returns {ClientHello} The constructed ClientHello object.
   */
  get build(): ClientHello;

  /**
   * Gets the protocol version.
   */
  get version(): Uint8Array;

  /**
   * Gets the random bytes.
   */
  get random(): Uint8Array;

  /**
   * Gets the session ID.
   */
  get sessionId(): Uint8Array;

  /**
   * Gets the cipher suites.
   */
  get ciphers(): Uint8Array;

  /**
   * Gets the compression methods.
   */
  get compression(): Uint8Array;

  /**
   * Gets the extensions.
   */
  get extensions(): Map<number, Uint8Array>;

  /**
   * Gets the X25519 group.
   */
  get x25519(): NamedGroup;

  /**
   * Gets the SECP256R1 group.
   */
  get p256(): NamedGroup;

  /**
   * Gets the SECP384R1 group.
   */
  get p384(): NamedGroup;

  /**
   * Gets the supported named groups.
   */
  get groups(): Map<number, NamedGroup>;

  /**
   * Updates the named group used for key exchange.
   * @param {NamedGroup} group - The named group.
   */
  updateNamedGroup(group: NamedGroup): void;
}




