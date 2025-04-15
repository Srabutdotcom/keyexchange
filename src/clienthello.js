//@ts-self-types = "../type/clienthello.d.ts"
import { Cipher, Constrained, Cookie, EarlyDataIndication, Extension, ExtensionType, KeyShareClientHello, NamedGroup, NamedGroupList, OfferedPsks, Padding, PskKeyExchangeMode, PskKeyExchangeModes, RecordSizeLimit, safeuint8array, ServerNameList, SignatureScheme, SignatureSchemeList, Uint16, Uint24, Version } from "./dep.ts";
import { Versions } from "@tls/extension"
import { parseItems } from "./utils.js"

export class ClientHello extends Uint8Array {
   #version
   #random
   #legacy_session_id
   #ciphers
   #legacy_compression_methods
   #extensions
   #groups
   #proto
   #keyshares
   #sni

   static create(...args) {
      return new ClientHello(...args)
   }
   static from = ClientHello.create
   constructor(...args) {
      args = (args[0] instanceof Uint8Array) ? sanitize(args[0]) : args
      super(...args)
   }
   get version() {
      this.#version ||= Version.from(this.subarray(0, 2))
      return this.#version
   }
   get legacy_version() { return this.version }
   get random() {
      this.#random ||= this.subarray(2, 34);
      return this.#random;
   }
   get legacy_session_id() {
      if (this.#legacy_session_id) return this.#legacy_session_id
      const lengthOf = this.at(34);
      if (lengthOf == 0) {
         this.#legacy_session_id = this.subarray(34, 35);
         this.#legacy_session_id.end = 35
      } else {
         const end = 35 + lengthOf
         this.#legacy_session_id = this.subarray(35, end);
         this.#legacy_session_id.end = end;
      }
      return this.#legacy_session_id
   }
   get session_id() { return this.legacy_session_id }
   get ciphers() {
      if (this.#ciphers) return this.#ciphers;
      const lengthOf = Uint16.from(this.subarray(this.legacy_session_id.end)).value;
      if (lengthOf < 2) throw Error(`expected at list one cipher`)
      const start = this.legacy_session_id.end + 2;
      const end = start + lengthOf;
      this.#ciphers = parseItems(this, start, lengthOf, Cipher);//
      this.#ciphers.end = end;
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
      const end = this.ciphers.end + 2;
      this.#legacy_compression_methods ||= this.subarray(this.ciphers.end, end);
      this.#legacy_compression_methods.end = end
      return this.#legacy_compression_methods
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const copy = this.subarray(this.legacy_compression_methods.end)
      const lengthOf = Uint16.from(copy).value;
      if (lengthOf < 8) throw TypeError(`Length min. 8 bytes`)
      if (lengthOf > 2 ** 16 - 2) throw TypeError(`Length max: ${2 ** 16 - 2}`)
      const output = new Map;
      let offset = 2;
      while (true) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension);
         extension.pos = offset + 2;
         output.set(extension.type, extension.data)
         if (offset >= lengthOf) break;
         if (offset >= copy.length) break;
      }
      this.#extensions ||= output;
      return this.#extensions;
   }
   get supported_versions(){
      const data = this.extensions.get(ExtensionType.SUPPORTED_VERSIONS);
      return Versions.from(data).versions;
   }
   get psk_key_exchange_modes(){
      const data = this.extensions.get(ExtensionType.PSK_KEY_EXCHANGE_MODES);
      return PskKeyExchangeModes.from(data).ke_modes
   }
   get supported_groups(){
      const data = this.extensions.get(ExtensionType.SUPPORTED_GROUPS);
      return NamedGroupList.from(data).named_group_list
   }
   get signature_algorithms(){
      const data = this.extensions.get(ExtensionType.SIGNATURE_ALGORITHMS);
      return SignatureSchemeList.from(data).supported_signature_algorithms
   }
   get server_names(){
      const data = this.extensions.get(ExtensionType.SERVER_NAME);
      return [...ServerNameList.from(data).serverNames].map(e=>e.name)
   }
   addBinders(binders) {
      const _psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      //const lengthOf = psk.data.length + binders.length;
      //const uint16 = Uint16.fromValue(lengthOf)
      const array = safeuint8array(this, binders);
      //array.set(uint16, psk.pos + 2);
      return new ClientHello(array)
   }
   binderPos() {
      const psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      return psk.pos + 4 + psk.data.identities.length
   }
   get handshake() {
      const handshake = safeuint8array(1, Uint24.fromValue(this.length), this);
      handshake.groups = this.groups;
      handshake.message = this
      return handshake;
   }
   get record() {
      const handshake = this.handshake
      const record = safeuint8array(22, Version.TLS10.byte, Uint16.fromValue(handshake.length), handshake);
      record.groups = this.groups;
      record.fragment = handshake;
      return record
   }
   set groups(groups) {
      this.#groups = groups;
   }
   get groups() {
      if (this.#groups) return this.#groups;
      this.#groups ||= this.extensions.get(ExtensionType.KEY_SHARE).data.keyShareEntries
      return this.#groups;
   }
   set proto(proto) {
      this.#proto = proto;
   }
   get proto() {
      return this.#proto;
   }
   set keyshares(keyshares) {
      this.#keyshares = keyshares;
   }
   get keyshares() {
      return this.#keyshares;
   }
   set sni(sni) {
      this.#sni = sni;
   }
   get sni() {
      return this.#sni;
   }
}

function sanitize(data) {
   return [sanitizeClientHello(data)]
}

function sanitizeClientHello(data) {
   let offset = 0;
   // client_version (2 bytes) + random (32 bytes)
   if (Version.from(data).value < 0x0300) return Alert.fromAlertDescription(AlertDescription.PROTOCOL_VERSION)
   offset += 2 + 32;

   // session_id
   const sessionIdLen = data[offset];
   if (sessionIdLen > 32) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE)
   offset += 1 + sessionIdLen;

   // cipher_suites
   const cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
   const _ciphers = parseItems(data, offset + 2, cipherSuitesLen, Cipher);
   offset += 2 + cipherSuitesLen;

   // compression_methods
   const compressionMethodsLen = data[offset];
   if (compressionMethodsLen !== 1) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE)
   offset += 1 + compressionMethodsLen;

   // extensions
   const extensionsLen = (data[offset] << 8) | data[offset + 1];
   const _extensions = parseItems(data, offset + 2, extensionsLen, Extension);
   offset += 2;

   if (offset + extensionsLen > data.length) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE);

   return data.subarray(0, offset + extensionsLen);
}

//const test_0 = new ClientHello(HandshakeType.CLIENT_HELLO.Uint8)

function _cipher_suites(array) {
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
         extension.parser = SignatureSchemeList; break;
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

export function clientHelloForm(...serverNames) {
   class ClientHelloForm {
      // ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      #version = Uint8Array.of(3, 3);
      // opaque Random[32];
      #random = crypto.getRandomValues(new Uint8Array(32));
      // opaque legacy_session_id<0..32>;
      #sessionId = Uint8Array.of(0)//safeuint8array(32, crypto.getRandomValues(new Uint8Array(32)));//
      // CipherSuite cipher_suites<2..2^16-2>;
      // uint8 CipherSuite[2];    /* Cryptographic suite selector */
      #ciphers = Uint8Array.of(0, 6, 19, 1, 19, 3, 19, 2);
      // opaque legacy_compression_methods<1..2^8-1>;
      #compression = Uint8Array.of(1, 0);
      #extensions = new Map([
         [
            ExtensionType.SUPPORTED_GROUPS,
            safeuint8array(
               Uint8Array.of(0, 6),
               NamedGroup.X25519.byte,
               NamedGroup.SECP256R1.byte,
               NamedGroup.SECP384R1.byte,
            )
         ],
         [
            ExtensionType.SIGNATURE_ALGORITHMS,
            safeuint8array(
               Uint8Array.of(0, 12),
               SignatureScheme.ECDSA_SECP256R1_SHA256.byte,
               SignatureScheme.ECDSA_SECP384R1_SHA384.byte,
               SignatureScheme.RSA_PSS_RSAE_SHA256.byte,
               SignatureScheme.RSA_PSS_RSAE_SHA384.byte,
               SignatureScheme.RSA_PSS_PSS_SHA256.byte,
               SignatureScheme.RSA_PSS_PSS_SHA384.byte,
            )
         ],
         [
            ExtensionType.SUPPORTED_VERSIONS,
            Uint8Array.of(2, 3, 4/* , 3, 3 */)
         ],
         [
            ExtensionType.PSK_KEY_EXCHANGE_MODES,
            Uint8Array.of(1, +PskKeyExchangeMode.PSK_DHE_KE)
         ]
      ])
      #groups = new Map([
         [NamedGroup.X25519, NamedGroup.X25519],
         [NamedGroup.SECP256R1, NamedGroup.SECP256R1],
         [NamedGroup.SECP384R1, NamedGroup.SECP384R1]
      ])
      constructor(...serverNames) {
         this.#extensions.set(
            ExtensionType.SERVER_NAME,
            ServerNameList.fromName(...serverNames))
         this.#extensions.set(
            ExtensionType.KEY_SHARE,
            KeyShareClientHello.fromKeyShareEntries(
               this.#groups.get(NamedGroup.X25519).keyShareEntry(),
               this.#groups.get(NamedGroup.SECP256R1).keyShareEntry(),
               this.#groups.get(NamedGroup.SECP384R1).keyShareEntry(),
            )
         )
      }
      get build() {
         const extensions = new Set
         let length = 0;
         for (const [key, value] of this.extensions) {
            const extension = Extension.create(key, value)
            extensions.add(extension);
            length += extension.length;
         }
         const clientHello = ClientHello.from(
            safeuint8array(
               this.version,
               this.random,
               this.sessionId,
               this.ciphers,
               this.compression,
               Uint16.fromValue(length),
               ...extensions
            ))
         clientHello.groups = this.#groups
         return clientHello;
      }
      get version() { return this.#version }
      get random() { return this.#random }
      get sessionId() { return this.#sessionId }
      get ciphers() { return this.#ciphers }
      get compression() { return this.#compression }
      get extensions() { return this.#extensions }
      get x25519() { return this.#groups.get(NamedGroup.X25519) }
      get p256() { return this.#groups.get(NamedGroup.SECP256R1) }
      get p384() { return this.#groups.get(NamedGroup.SECP384R1) }
      get groups() { return this.#groups }
      updateNamedGroup(group) {
         this.#groups.set(group, group)
         this.#extensions.set(
            ExtensionType.KEY_SHARE,
            KeyShareClientHello.fromKeyShareEntries(
               group.keyShareEntry(),
            )
         )
      }
   }
   return new ClientHelloForm(...serverNames)
}

