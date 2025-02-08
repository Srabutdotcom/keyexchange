//@ts-self-types="../type/serverhello.d.ts"
import { Cipher, ContentType, Extension, ExtensionType, HandshakeType, KeyShareServerHello, SupportedVersions, Uint16, Uint24, Version } from "./dep.ts";


export class ServerHello extends Uint8Array {
   #legacy_version // 0x0303;    /* TLS v1.2 */
   #random
   #legacy_session_id_echo
   #cipher_suite
   #legacy_compression_method
   #extensions
   static create(...args){
      return new ServerHello(...args)
   }
   static from = ServerHello.create
   constructor(...args) {
      args = (args.at(0) instanceof Uint8Array) ? sanitize(...args) : args
      super(...args)
   }
   get version() {
      this.#legacy_version ||= Version.from(this.subarray(0, 2))
      return this.#legacy_version
   }
   get random() {
      this.#random ||= this.subarray(2, 34);
      return this.#random;
   }
   get legacy_session_id() {
      if (this.#legacy_session_id_echo) return this.#legacy_session_id_echo
      const lengthOf = this.at(34);
      if (lengthOf == 0) {
         this.#legacy_session_id_echo = this.subarray(34, 35);
      } else {
         this.#legacy_session_id_echo = this.subarray(35, 35 + lengthOf)
      }
      return this.#legacy_session_id_echo
   }
   get cipher() {
      this.#cipher_suite ||= Cipher.from(this.subarray(35 + this.at(34)));
      return this.#cipher_suite;
   }
   get legacy_compression_methods() {
      const start = 35 + this.at(34) + 2
      this.#legacy_compression_method ||= this.subarray(start, start + 1)
      return this.#legacy_compression_method
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const copy = this.subarray(34 + this.legacy_session_id.length + this.cipher.length + 1)
      const lengthOf = Uint16.from(copy).value;
      const output = new Map;
      for (let offset = 2; offset < lengthOf + 2;) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension);
         output.set(extension.extension_type, extension.extension_data)
      }
      this.#extensions ||= output;
      return this.#extensions
   }
}

function sanitize(...args) {
   try {
      if (Version.from(args[0]) instanceof Version) return args
      throw Error
   } catch (_error) {
      try {
         if (HandshakeType.from(args[0]) == HandshakeType.SERVER_HELLO) {
            const lengthOf = Uint24.from(args[0].subarray(1)).value;
            return [args[0].subarray(4, 4 + lengthOf)]
         }
         throw Error
      } catch (_error) {
         try {
            const contentType = ContentType.from(args[0]);
            const handshakeType = HandshakeType.from(args[0].subarray(5));
            const lengthOf = Uint24.from(args[0].subarray(6)).value;
            const conditions = [
               contentType == ContentType.HANDSHAKE,
               handshakeType == HandshakeType.SERVER_HELLO
            ]
            if (conditions.every(e => e == true)) return [args[0].subarray(9, 9 + lengthOf)]
            throw Error;
         } catch (error) {
            throw error;
         }
      }
   }
}

function parseExtension(extension) {
   const { extension_type, extension_data } = extension;
   switch (extension_type) {
      case ExtensionType.KEY_SHARE: {
         extension.extension_data = KeyShareServerHello.from(extension_data); break;
      }
      case ExtensionType.SUPPORTED_VERSIONS: {
         extension.extension_data = SupportedVersions.fromServer_hello(extension_data); break;
      }
      default:
         break;
   }
}

