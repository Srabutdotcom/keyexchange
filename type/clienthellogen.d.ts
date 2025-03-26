import { ClientHello } from "../src/mod.ts";

/**
 * Generates a ClientHello message with the given server names.
 * 
 * @param {string[]} serverNames - List of server names to include in the SNI extension.
 * @returns {ClientHello} - The generated ClientHello object.
 */
export function clientHelloGen(...serverNames: string[]): ClientHello;

/**
 * Generates a ClientHello message with a session ID and server names.
 * 
 * @param {Uint8Array} sessionId - The session ID to include in the ClientHello message.
 * @param {string[]} serverNames - List of server names to include in the SNI extension.
 * @returns {ClientHello} - The generated ClientHello object.
 */
export function clientHelloGenWithSessionId(sessionId: Uint8Array, ...serverNames: string[]): ClientHello;

/**
 * Updates the ClientHello message with a new key exchange group.
 *
 * @param {ClientHello} clientHello - The existing ClientHello object to update.
 * @param {number} group - The key exchange group to set.
 * @returns {ClientHello} - The updated ClientHello object.
 */
export function updateClientHellogroup(clientHello: ClientHello, group: number): ClientHello;