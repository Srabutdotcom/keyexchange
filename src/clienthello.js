//@ts-self-types = "../type/clienthello.d.ts"
import {
   Uint8, Uint16, Uint24, Version, Constrained, Cipher, Struct,
   Extension, ExtensionType,
   NamedGroupList, NamedGroup, RecordSizeLimit,
   KeyShareClientHello, SupportedVersions, ServerNameList, PskKeyExchangeModes,
   Cookie, Supported_signature_algorithms,
   HandshakeType,
   OfferedPsks,
   EarlyDataIndication,
   Padding,
   safeuint8array,
   Handshake,
} from "./dep.ts"

export class ClientHello extends Struct {
   legacy_version;
   random; // offset 2, length 32
   legacy_session;// offset = 32, length = 1;
   cipher_suites; // offset = 33;
   legacy_compression_methods; // offset = 33 + cipher_suites.length
   extensions;
   ext = new Map;
   static fromHandShake(handshake) {
      const copy = Uint8Array.from(handshake);
      let offset = 0;
      const _type = HandshakeType.from(copy); offset += 1;
      const lengthOf = Uint24.from(copy.subarray(offset)).value; offset += 3;
      return ClientHello.from(copy.subarray(offset, offset + lengthOf));
   }
   static fromHandshake = ClientHello.fromHandShake
   static from(array) {
      const copy = Uint8Array.from(array);
      let offset = 0
      const _legacy_version = Version.from(copy.subarray(offset)); offset += 2;
      const random = copy.subarray(offset, offset + 32); offset += 32;
      const legacy_session = Legacy_session_id.from(copy.subarray(offset)); offset += legacy_session.length;
      const cipher_suites = Cipher_suites.from(copy.subarray(offset)); offset += cipher_suites.length;
      const _legacy_compression_methods = Legacy_compression_methods.from(copy.subarray(offset)); offset += _legacy_compression_methods.length;
      const extensions = Extensions.from(copy.subarray(offset));
      return new ClientHello(random, legacy_session, cipher_suites, ...extensions.extensions)
   }
   constructor(
      random = crypto.getRandomValues(new Uint8Array(32)),
      legacy_session = new Legacy_session_id,
      cipher_suites = new Cipher_suites(Cipher.AES_128_GCM_SHA256, Cipher.AES_256_GCM_SHA384),
      ...extensions
   ) {

      const legacy_version = Version.legacy.protocolVersion();
      //const random = crypto.getRandomValues(new Uint8Array(32));
      // const legacy_session = new Legacy_session_id;
      //const cipher_suites = new Cipher_suites(Cipher.AES_128_GCM_SHA256, Cipher.AES_256_GCM_SHA384);
      const legacy_compression_methods = new Legacy_compression_methods;

      super(
         legacy_version,
         random,
         legacy_session,
         cipher_suites,
         legacy_compression_methods,
         Extensions.fromExtension(...extensions)
      )
      this.legacy_version = legacy_version;
      this.random = random;
      this.legacy_session = legacy_session;
      this.cipher_suites = cipher_suites;
      this.legacy_compression_methods = legacy_compression_methods
      let offset = legacy_version.length + random.length + legacy_session.length
         + cipher_suites.length + legacy_compression_methods.length;
      this.extensions = extensions;
      for (const ex of extensions) {
         this.ext.set(ex.extension_type?.name, { pos: offset + 2, data: ex.extension_data });
         offset += ex.length;
      }
   }
   static fromServerName(serverName) {
      return new ClientHello(undefined, undefined, undefined,
         Uint8Array.of(
            0, 10, 0, 12, 0, 10, 0, 29, 0, 23, 0, 24, 0, 30, 0, 25, // ExtensionType.SUPPORTED_GROUPS.extension(NamedGroupList.default());
            0, 13, 0, 18, 0, 16, 8, 6, 8, 5, 8, 4, 8, 7, 8, 8, 6, 3, 5, 3, 4, 3, // ExtensionType.SIGNATURE_ALGORITHMS.extension(Supported_signature_algorithms.default());
            0, 43, 0, 3, 2, 3, 4, // ExtensionType.SUPPORTED_VERSIONS.extension(SupportedVersions.forClient_hello())
            0, 45, 0, 2, 1, 1 // ExtensionType.PSK_KEY_EXCHANGE_MODES.extension(PskKeyExchangeModes.default())
         ),
         ExtensionType.SERVER_NAME.extension(ServerNameList.fromName(serverName)),
         ExtensionType.KEY_SHARE.extension(KeyShareClientHello.fromKeyShareEntries(
            NamedGroup.X25519.keyShareEntry(),
            NamedGroup.SECP256R1.keyShareEntry()
         ))
      )
   }

   get handshake() { return new Handshake(HandshakeType.CLIENT_HELLO, this) }
   get record() { return this.handshake.record }

   addBinders(binders) {
      const psk = this.ext.get('PRE_SHARED_KEY');
      const lengthOf = psk.data.length + binders.length;
      const uint16 = Uint16.fromValue(lengthOf)
      const array = safeuint8array(this, binders);
      array.set(uint16, psk.pos + 2);
      return ClientHello.from(array)
   }
   binderPos() {
      const psk = this.ext.get('PRE_SHARED_KEY');
      return psk.pos + 4 + psk.data.identities.length
   }
}

export class Cipher_suites extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      const ciphers = [];
      for (let offset = 2; offset < lengthOf + 2; offset += 2) {
         const cipher = Cipher.from(copy.subarray(offset));
         ciphers.push(cipher)
      }
      return new Cipher_suites(...ciphers)
   }
   constructor(...ciphers) {
      super(2, 2 ** 16 - 2, ...ciphers.map(e => e.Uint16))
      this.ciphers = new Set(ciphers);
   }
}

class Extensions extends Constrained {
   static fromExtension(...extensions) { return new Extensions(...extensions) }
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      const extensions = [];
      let offset = 2;
      //for (let offset = 2; offset < lengthOf + 2;) {
      while (true) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension);
         extensions.push(extension)
         if (offset >= lengthOf) break;
         if (offset >= copy.length) break;
      }
      return new Extensions(...extensions)
   }
   constructor(...extensions) {
      super(8, 2 ** 16 - 1, ...extensions)
      this.extensions = extensions
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

class Legacy_session_id extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint8.from(copy).value;
      if (lengthOf == 0) return new Legacy_session_id;
      return new Legacy_session_id(copy.subarray(1, 1 + lengthOf))
   }
   constructor(opaque = new Uint8Array) {
      super(0, 32, opaque)
      this.opaque = opaque
   }
}

class Legacy_compression_methods extends Constrained {
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint8.from(copy).value;
      return new Legacy_compression_methods(copy.subarray(1, 1 + lengthOf))
   }
   constructor(opaque = Uint8Array.of(0)) {
      super(0, 2 ** 8 - 1, opaque)
      this.opaque = opaque
   }
}

