//@ts-self-types = "../type/clienthello.d.ts"
import { Cipher, Constrained, ContentType, Cookie, EarlyDataIndication, Extension, ExtensionType, HandshakeType, KeyShareClientHello, NamedGroupList, OfferedPsks, Padding, parseItems, PskKeyExchangeModes, RecordSizeLimit, safeuint8array, ServerNameList, Supported_signature_algorithms, SupportedVersions, Uint16, Uint24, Version } from "./dep.ts";

export class ClientHello extends Uint8Array {
   #version
   #random
   #legacy_session_id
   #ciphers
   #legacy_compression_methods
   #extensions
   static create(...args){
      return new ClientHello(...args)
   }
   static from = ClientHello.create
   constructor(...args) {
      args = (args.at(0) instanceof Uint8Array)? sanitize(...args): args
      super(...args)
   }
   get version() {
      this.#version ||= Version.from(this.subarray(0, 2))
      return this.#version
   }
   get random() {
      this.#random ||= this.subarray(2, 34);
      return this.#random;
   }
   get legacy_session_id() {
      if (this.#legacy_session_id) return this.#legacy_session_id
      const lengthOf = this.at(34);
      if (lengthOf == 0) {
         this.#legacy_session_id = this.subarray(34, 35);
      } else {
         this.#legacy_session_id = this.subarray(35, 35 + lengthOf)
      }
      return this.#legacy_session_id
   }
   get ciphers() {
      this.#ciphers ||= Cipher_suites.from(this.subarray(35 + this.at(34)));
      return this.#ciphers;
   }
   /**
    * For every TLS 1.3 ClientHello, this vector
      MUST contain exactly one byte, set to zero, which corresponds to
      the "null" compression method in prior versions of TLS.  If a
      TLS 1.3 ClientHello is received with any other value in this
      field, the server MUST abort the handshake with an
      "illegal_parameter" alert.
    */
   get legacy_compression_methods() {
      if (this.#legacy_compression_methods) return this.#legacy_compression_methods
      const offset = 34 + this.legacy_session_id.length + this.ciphers.length;
      this.#legacy_compression_methods ||= this.subarray(offset, offset + 2);
      return this.#legacy_compression_methods
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const copy = this.subarray(34 + this.legacy_session_id.length + this.ciphers.length + 2)
      const lengthOf = Uint16.from(copy).value;
      if (lengthOf < 8) throw TypeError(`Length min. 8 bytes`)
      if (lengthOf > 2 ** 16 - 2) throw TypeError(`Length max: ${2 ** 16 - 2}`)
      const output = new Map;
      let offset = 2;
      while (true) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension);
         extension.extension_data.pos = offset + 2;
         output.set(extension.extension_type, extension.extension_data)
         if (offset >= lengthOf) break;
         if (offset >= copy.length) break;
      }
      this.#extensions ||= output;
      return this.#extensions;
   }
   addBinders(binders) {
      const psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      const lengthOf = psk.length + binders.length;
      const uint16 = Uint16.fromValue(lengthOf)
      const array = safeuint8array(this, binders);
      array.set(uint16, psk.pos + 2);
      return new ClientHello(array)
   }
   binderPos() {
      const psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      return psk.pos + 4 + psk.identities.length
   }
}

function sanitize(...args) {
   try {
      if(Version.from(...args) instanceof Version) return args
      throw Error
   } catch (_error) {
      try {
         if(HandshakeType.from(args[0]) == HandshakeType.CLIENT_HELLO){
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
               handshakeType == HandshakeType.CLIENT_HELLO
            ]
            if(conditions.every(e=>e==true))return [args[0].subarray(9, 9 + lengthOf)]
            throw Error;
         } catch (error) {
            throw error;
         }
      }
   }
}

//const test_0 = new ClientHello(HandshakeType.CLIENT_HELLO.Uint8)

class Cipher_suites extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      const ciphers = parseItems(copy, 2, lengthOf, Cipher);
      return new Cipher_suites(...ciphers)
   }
   constructor(...ciphers) {
      super(2, 2 ** 16 - 2, ...ciphers.map(e => e.Uint16))
      this.ciphers = ciphers;
   }
}

function parseExtension(extension) {
   const { extension_type, extension_data } = extension;
   switch (extension_type) {
      case ExtensionType.SUPPORTED_GROUPS: {
         extension.extension_data = NamedGroupList.from(extension_data); break;
      }
      case ExtensionType.KEY_SHARE: {
         extension.extension_data = KeyShareClientHello.from(extension_data); break;
      }
      case ExtensionType.SUPPORTED_VERSIONS: {
         extension.extension_data = SupportedVersions.fromClient_hello(extension_data); break;
      }
      case ExtensionType.SIGNATURE_ALGORITHMS: {
         extension.extension_data = Supported_signature_algorithms.from(extension_data); break;
      }
      case ExtensionType.SERVER_NAME: {
         extension.extension_data = extension_data.length ? ServerNameList.from(extension_data) : extension_data; break;
      }
      case ExtensionType.PSK_KEY_EXCHANGE_MODES: {
         extension.extension_data = PskKeyExchangeModes.from(extension_data); break;
      }
      case ExtensionType.COOKIE: {
         extension.extension_data = Cookie.from(extension_data); break;
      }
      case ExtensionType.RECORD_SIZE_LIMIT: {
         extension.extension_data = RecordSizeLimit.from(extension_data); break;
      }
      case ExtensionType.EARLY_DATA: {
         extension.extension_data = EarlyDataIndication.from(extension_data); break;
      }
      case ExtensionType.PADDING: {
         extension.extension_data = Padding.from(extension_data); break;
      }
      case ExtensionType.PRE_SHARED_KEY: {
         extension.extension_data = OfferedPsks.from(extension_data); break;
      }
      default:
         break;
   }
}

