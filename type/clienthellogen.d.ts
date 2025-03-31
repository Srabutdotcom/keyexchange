import { ClientHello } from "../src/mod.ts";

/**
 * Generates a TLS 1.3 ClientHello message.
 *
 * @param {Object} option - Configuration options for the ClientHello.
 * @param {Uint8Array} [option.sessionId=Uint8Array.of(0)] - The session ID.
 * @param {Uint8Array} [option.signatureSchemeList=Uint8Array.of(4, 3, 5, 3, 8, 4, 8, 5, 8, 7, 8, 8, 8, 9, 8, 10)] - List of supported signature schemes.
 * @param {string[]} [option.serverNames=[]] - List of server names for the SNI extension.
 * @returns {Uint8Array} The encoded ClientHello message.
 */
export function clientHelloGen(option?: {
   sessionId?: Uint8Array;
   signatureSchemeList?: Uint8Array;
   serverNames?: string[];
 }): ClientHello;
 

/**
 * Updates the ClientHello message with a new key exchange group.
 *
 * @param {ClientHello} clientHello - The existing ClientHello object to update.
 * @param {number} group - The key exchange group to set.
 * @returns {ClientHello} - The updated ClientHello object.
 */
export function updateClientHellogroup(clientHello: ClientHello, group: number): ClientHello;