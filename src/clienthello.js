//@ts-self-types = "../type/clienthello.d.ts"
import { Cipher, Constrained, ContentType, Cookie, EarlyDataIndication, Extension, ExtensionType, HandshakeType, KeyShareClientHello, NamedGroup, NamedGroupList, OfferedPsks, Padding, parseItems, PskKeyExchangeMode, PskKeyExchangeModes, RecordSizeLimit, safeuint8array, ServerNameList, SignatureScheme, SignatureSchemeList, Supported_signature_algorithms, Uint16, Uint24, Version } from "./dep.ts";
import { Versions } from "@tls/extension"

export class ClientHello extends Uint8Array {
   #version
   #random
   #legacy_session_id
   #ciphers
   #legacy_compression_methods
   #extensions
   #namedGroup
   static build = buildClientHello;
   static create(...args) {
      return new ClientHello(...args)
   }
   static from = ClientHello.create
   constructor(...args) {
      args = (args.at(0) instanceof Uint8Array) ? sanitize(...args) : args
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
      this.#ciphers ||= /* _Cipher_suites.from */cipher_suites(this.subarray(35 + this.at(34)));
      /* console.log(this.#ciphers);
      const test = cipher_suites(this.subarray(35 + this.at(34))) 
      console.log(test) */
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
         extension.pos = offset + 2;
         output.set(extension.type, extension)
         if (offset >= lengthOf) break;
         if (offset >= copy.length) break;
      }
      this.#extensions ||= output;
      return this.#extensions;
   }
   addBinders(binders) {
      const psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      const lengthOf = psk.data.length + binders.length;
      const uint16 = Uint16.fromValue(lengthOf)
      const array = safeuint8array(this, binders);
      array.set(uint16, psk.pos + 2);
      return new ClientHello(array)
   }
   binderPos() {
      const psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      return psk.pos + 4 + psk.data.identities.length
   }
   get handshake(){
      return safeuint8array(1, Uint24.fromValue(this.length), this)
   }
   get record(){
      const handshake = this.handshake
      return safeuint8array(22, Version.legacy.byte, Uint16.fromValue(handshake.length), handshake)
   }
   set namedGroup(group){
      this.#namedGroup = group;
   }
   get namedGroup(){
      return this.#namedGroup;
   }
   get privateKey(){
      return this.namedGroup.privateKey;
   }
   get publicKey(){
      return this.namedGroup.publicKey;
   }
}

function sanitize(...args) {
   try {
      if (Version.from(args[0]) instanceof Version) return args
      throw Error
   } catch (_error) {
      try {
         if (HandshakeType.from(args[0]) == HandshakeType.CLIENT_HELLO) {
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
            if (conditions.every(e => e == true)) return [args[0].subarray(9, 9 + lengthOf)]
            throw Error;
         } catch (error) {
            throw error;
         }
      }
   }
}

//const test_0 = new ClientHello(HandshakeType.CLIENT_HELLO.Uint8)

function cipher_suites(array) {
   const lengthOf = Uint16.from(array).value;
   if (lengthOf < 2) throw Error(`expected at list one cipher`)
   const ciphers = parseItems(array, 2, lengthOf, Cipher);
   ciphers.length = 2 + lengthOf;
   return ciphers
}

class _Cipher_suites extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      const ciphers = parseItems(copy, 2, lengthOf, Cipher);
      return new _Cipher_suites(...ciphers)
   }
   constructor(...ciphers) {
      super(2, 2 ** 16 - 2, ...ciphers.map(e => e.Uint16))
      this.ciphers = ciphers;
   }
}

function parseExtension(extension) {
   switch (extension.type) {
      case ExtensionType.SUPPORTED_GROUPS: {
         extension.parser = NamedGroupList; break;
      }
      case ExtensionType.KEY_SHARE: {
         extension.parser = KeyShareClientHello; break;
      }
      case ExtensionType.SUPPORTED_VERSIONS: {
         extension.parser = Versions; break;
      }
      case ExtensionType.SIGNATURE_ALGORITHMS: {
         extension.parser = Supported_signature_algorithms; break;
      }
      case ExtensionType.SERVER_NAME: {
         extension.parser = extension.data.length ? ServerNameList : undefined; break;
      }
      case ExtensionType.PSK_KEY_EXCHANGE_MODES: {
         extension.parser = PskKeyExchangeModes; break;
      }
      case ExtensionType.COOKIE: {
         extension.parser = Cookie; break;
      }
      case ExtensionType.RECORD_SIZE_LIMIT: {
         extension.parser = RecordSizeLimit; break;
      }
      case ExtensionType.EARLY_DATA: {
         extension.parser = EarlyDataIndication; break;
      }
      case ExtensionType.PADDING: {
         extension.parser = Padding; break;
      }
      case ExtensionType.PRE_SHARED_KEY: {
         extension.parser = OfferedPsks; break;
      }
      default:
         break;
   }
}

export function buildClientHello(...serverNames) {
   // derived from _clientHelloHead
   const clientHelloHead = Uint8Array.of(3, 3, 238, 224, 243, 110, 198, 197, 21, 0, 31, 62, 170, 168, 11, 114, 76, 23, 125, 57, 4, 182, 125, 129, 85, 232, 67, 131, 111, 67, 131, 169, 63, 58, 0, 0, 6, 19, 1, 19, 2, 19, 3, 1, 0);

   // to make random 32
   crypto.getRandomValues(clientHelloHead.subarray(2, 2 + 32));

   // derived from _extensionList
   const extension_1 = Uint8Array.of(0, 10, 0, 4, 0, 2, 0, 29, 0, 13, 0, 24, 0, 22, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 0, 43, 0, 3, 2, 3, 4, 0, 45, 0, 2, 1, 1);

   const namedGroup = NamedGroup.X25519;

   const key_share = Extension.create(
      ExtensionType.KEY_SHARE,
      KeyShareClientHello.fromKeyShareEntries(
         namedGroup.keyShareEntry()
      )
   )

   const sni = Extension.create(
      ExtensionType.SERVER_NAME,
      ServerNameList.fromName(...serverNames)
   );

   const exts = safeuint8array(extension_1, key_share, sni);

   const extensions = safeuint8array(Uint16.fromValue(exts.length), exts);

   const clientHello = ClientHello.from(safeuint8array(clientHelloHead, extensions))
   clientHello.namedGroup = namedGroup
   return clientHello
}

const _legacy = Version.legacy.byte; 
const ciphers = ciphersFrom(
   Cipher.AES_128_GCM_SHA256,
   Cipher.AES_256_GCM_SHA384,
   Cipher.CHACHA20_POLY1305_SHA256
)

function ciphersFrom(...ciphers) {
   const _merged = safeuint8array(...ciphers.map(e => e.byte));
   const result = safeuint8array(Uint16.fromValue(_merged.length), _merged)
   return result;
}

const _clientHelloHead = safeuint8array(
   Version.legacy.byte,
   crypto.getRandomValues(new Uint8Array(32)),
   Uint8Array.of(0),
   ciphers,
   Uint8Array.of(1, 0),
   //safeuint8array(Uint16.fromValue(extensionList.length), extensionList)
);


const _extensionList = safeuint8array(
   Extension.create(
      ExtensionType.SUPPORTED_GROUPS,
      new NamedGroupList(
         NamedGroup.X25519,
         /* NamedGroup.X448,
         NamedGroup.SECP521R1,
         NamedGroup.SECP384R1,
         NamedGroup.SECP256R1 */
      )
   ),
   Extension.create(
      ExtensionType.SIGNATURE_ALGORITHMS,
      new SignatureSchemeList(
         SignatureScheme.RSA_PSS_PSS_SHA256,
         SignatureScheme.RSA_PSS_PSS_SHA384,
         SignatureScheme.RSA_PSS_PSS_SHA512,
         SignatureScheme.RSA_PSS_RSAE_SHA256,
         SignatureScheme.RSA_PSS_RSAE_SHA384,
         SignatureScheme.RSA_PSS_RSAE_SHA512,
         SignatureScheme.ECDSA_SECP256R1_SHA256,
         SignatureScheme.ECDSA_SECP384R1_SHA384,
         SignatureScheme.ECDSA_SECP521R1_SHA512,
         SignatureScheme.ED25519,
         SignatureScheme.ED448
      )
   ),
   Extension.create(
      ExtensionType.SUPPORTED_VERSIONS,
      Versions.defaultOne()
   ),
   Extension.create(
      ExtensionType.PSK_KEY_EXCHANGE_MODES,
      new PskKeyExchangeModes(PskKeyExchangeMode.PSK_DHE_KE)
   ),
   /* Extension.create(
      ExtensionType.KEY_SHARE,
      KeyShareClientHello.fromKeyShareEntries(
         NamedGroup.X25519.keyShareEntry(),
         NamedGroup.X448.keyShareEntry(),
         NamedGroup.SECP521R1.keyShareEntry(),
         NamedGroup.SECP384R1.keyShareEntry(),
         NamedGroup.SECP256R1.keyShareEntry(),
      )
   ),
   Extension.create(
      ExtensionType.SERVER_NAME,
      new ServerNameList(ServerName.fromName('smtp.gmail.com'))
   ) */
)


