import { ClientHello, ServerHello } from "../src/mod.ts";

/**
 * Generates a ServerHello message based on the provided ClientHello.
 * If the `clientHello` parameter is not an instance of `ClientHello`, it is converted.
 *
 * @param {ClientHello | Uint8Array} clientHello - The ClientHello message or its byte representation.
 * @returns {ServerHello} The generated ServerHello message.
 */
export function serverHelloGen(clientHello: ClientHello | Uint8Array): ServerHello;