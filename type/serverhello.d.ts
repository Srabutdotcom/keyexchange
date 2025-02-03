import {
   Cipher,
   Struct,
   Uint8,
   Version,
   TLSPlaintext,
   Handshake
} from "../src/dep.ts";

import { ClientHello } from "../src/clienthello.js";

// Define the type here instead of importing it
export type Legacy_session_id = Uint8Array;

/**
 * Represents a ServerHello message.
 */
export class ServerHello extends Struct {
   legacy_version: Version;
   random: Uint8Array;
   legacy_session_id_echo: Legacy_session_id;
   cipher_suite: Cipher;
   legacy_compression_method: Uint8;
   extensions: any[];
   ext: Record<string, any>;

   static fromClient_hello: (clientHello: ClientHello) => ServerHello;

   /**
    * Parses a ServerHello from a Handshake message.
    * @param handshake - The Handshake message.
    * @returns A new ServerHello instance.
    */
   static fromHandShake(handshake: Uint8Array): ServerHello;

   static fromHandshake: typeof ServerHello.fromHandShake;

   /**
    * Parses a ServerHello from a raw byte array.
    * @param array - The input Uint8Array.
    * @returns A new ServerHello instance.
    */
   static from(array: Uint8Array): ServerHello;

   constructor(
      random?: Uint8Array,
      legacy_session_id_echo?: Legacy_session_id,
      cipher_suite?: Cipher,
      ...extensions: any[]
   );

   /**
    * Gets the handshake message.
    */
   get handshake(): Handshake;

   /**
    * Gets the record layer representation.
    */
   get record(): TLSPlaintext;
}





