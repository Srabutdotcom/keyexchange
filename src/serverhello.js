//@ts-self-types="../type/serverhello.d.ts"
import { Cipher, Constrained, Extension, Struct, Uint8, Uint16, Version, ExtensionType } from "./dep.ts";
import { KeyShareServerHello, SupportedVersions, NamedGroup, Selected_version } from "./dep.ts"
import { selectKeyExchange } from "./utils.js";
import { HandshakeType, ContentType, Uint24 } from "./dep.ts";

export class ServerHello extends Struct {
   legacy_version;
   random;
   legacy_session_id_echo;
   cipher_suite;
   legacy_compression_method; // Uint8 = 0
   extensions;
   ext = {};
   static fromClient_hello = fromClient_hello;
   static fromHandShake(handshake) {
      const copy = Uint8Array.from(handshake);
      let offset = 0;
      const _type = HandshakeType.from(copy); offset += 1;
      const lengthOf = Uint24.from(copy.subarray(offset)).value; offset += 3;
      return ServerHello.from(copy.subarray(offset, offset + lengthOf));
   }
   static from(array) {
      const copy = Uint8Array.from(array);
      let offset = 0
      const _legacy_version = Version.from(copy.subarray(offset)); offset += 2;
      const random = copy.subarray(offset, offset + 32); offset += 32;
      const legacy_session_id_echo = Legacy_session_id.from(copy.subarray(offset)); offset += legacy_session_id_echo.length;
      const cipher_suite = Cipher.from(copy.subarray(offset)).Uint16; offset += cipher_suite.length;
      const _legacy_compression_methods = Uint8.from(copy.subarray(offset)); offset += _legacy_compression_methods.length;
      const extensions = Extensions.from(copy.subarray(offset));
      return new ServerHello(random, legacy_session_id_echo, cipher_suite, ...extensions.extensions)
   }
   constructor(
      random = crypto.getRandomValues(new Uint8Array(32)),
      legacy_session_id_echo,
      cipher_suite,
      ...extensions
   ) {
      const legacy_version = Version.legacy.protocolVersion();
      const legacy_compression_method = Uint8.fromValue(0);
      super(
         legacy_version,
         random,
         legacy_session_id_echo,
         cipher_suite,
         legacy_compression_method,
         Extensions.fromExtension(...extensions)
      )
      this.legacy_version = legacy_version;
      this.random = random;
      this.legacy_session_id_echo = legacy_session_id_echo;
      this.cipher_suite = cipher_suite;
      this.legacy_compression_method = legacy_compression_method
      this.extensions = extensions;
      for (const ex of extensions) {
         this.ext[ex.extension_type?.name] = ex.extension_data
      }
   }
   toRecord() { return ContentType.HANDSHAKE.tlsPlaintext(
      HandshakeType.SERVER_HELLO.handshake(this)
   ) }
}

class Extensions extends Constrained {
   static fromExtension(...extensions) { return new Extensions(...extensions) }
   static from(array) {
      const copy = Uint8Array.from(array);
      const lengthOf = Uint16.from(copy).value;
      const extensions = [];
      for (let offset = 2; offset < lengthOf + 2;) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension);
         extensions.push(extension)
      }
      return new Extensions(...extensions)
   }
   constructor(...extensions) {
      super(8, 2 ** 16 - 1, ...extensions)
      this.extensions = extensions
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

function fromClient_hello(clientHello) {
   const { legacy_session, cipher_suites, ext } = clientHello;
   const { ciphers } = cipher_suites;
   const KEY_SHARE = ext.get('KEY_SHARE');
   const { keyShareEntries } = KEY_SHARE.data;
   const cipherPreferences = new Set([Cipher.AES_128_GCM_SHA256, Cipher.AES_256_GCM_SHA384, Cipher.CHACHA20_POLY1305_SHA256]);
   const namedGroupPreferences = new Set([NamedGroup.X25519.name, NamedGroup.SECP256R1.name, NamedGroup.SECP384R1.name])
   const cipher = cipherPreferences.intersection(ciphers).values().next().value//selectFirstMatch(ciphers, cipherPreferences);
   const namedGroup = selectKeyExchange(keyShareEntries, namedGroupPreferences)

   return new ServerHello(undefined, legacy_session, cipher,
      ExtensionType.SUPPORTED_VERSIONS.extension(Selected_version.default()),
      ExtensionType.KEY_SHARE.extension(KeyShareServerHello.fromKeyShareEntry(
         namedGroup.group.keyShareEntry()
      ))
   )
}