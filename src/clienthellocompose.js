//@ts-self-types="../type/clienthellocompose.d.ts"
import { Cipher, NamedGroup, PskKeyExchangeMode, Version, SignatureScheme, Extension, ExtensionType, ServerNameList, NamedGroupList, SignatureSchemeList, Versions, PskKeyExchangeModes, KeyShareClientHello, vector16, unity, vector8, vector, Alert, AlertDescription, parseItems } from "../src/dep.ts";

const defaultOption = {
   legacy_version: Uint8Array.of(3, 3),
   random: crypto.getRandomValues(new Uint8Array(32)),
   session_id: new Uint8Array,
   legacy_session_id: new Uint8Array,
   ciphers: [
      Cipher.AES_128_GCM_SHA256,
      Cipher.AES_256_GCM_SHA384,
      Cipher.CHACHA20_POLY1305_SHA256
   ],
   legacy_compression_methods: Uint8Array.of(1, 0),
   // extensions/
   supported_versions: [Version.TLS13],
   psk_key_exchange_modes: [PskKeyExchangeMode.PSK_DHE_KE],
   supported_groups: [
      NamedGroup.X25519,
      NamedGroup.SECP256R1,
      NamedGroup.SECP384R1,
      NamedGroup.SECP521R1,
      NamedGroup.X448
   ],
   signature_algorithms: [
      SignatureScheme.ECDSA_SECP256R1_SHA256,
      SignatureScheme.ECDSA_SECP384R1_SHA384,
      SignatureScheme.ECDSA_SECP521R1_SHA512,
      SignatureScheme.RSA_PSS_RSAE_SHA256,
      SignatureScheme.RSA_PSS_RSAE_SHA384,
      SignatureScheme.RSA_PSS_RSAE_SHA512,
      SignatureScheme.RSA_PSS_PSS_SHA256,
      SignatureScheme.RSA_PSS_PSS_SHA384,
      SignatureScheme.RSA_PSS_PSS_SHA512
   ],
   server_names: []
}

export function clientHelloCompose(option = defaultOption, defaults = defaultOption) {
   const {
      legacy_version,
      random,
      session_id,
      ciphers,
      legacy_compression_methods,
      // extensions
      supported_versions,
      psk_key_exchange_modes,
      supported_groups,
      signature_algorithms,
      server_names = []
   } = {...defaults, ...option};

   // versions
   const legacy_session_id_0 = legacy_session_id(session_id);
   const cipher_suites_0 = cipher_suites(...ciphers)

   // extension creation
   // Extension extensions<8..2^16-1>;
   const sni_extension_0 = sni_extension(...server_names);
   const supported_groups_extension_0 = supported_groups_extension(...supported_groups);
   const signature_algorithms_extension_0 = signature_algorithms_extension(...signature_algorithms)
   const supported_versions_extension_0 = supported_versions_extension(...supported_versions)
   const psk_key_exchange_modes_extension_0 = psk_key_exchange_modes_extension(...psk_key_exchange_modes)
   const key_share_clienthello_extension_0 = key_share_clienthello_extension(...supported_groups)

   const extensions_0 = extensions(
      sni_extension_0,
      supported_groups_extension_0,
      signature_algorithms_extension_0,
      supported_versions_extension_0,
      psk_key_exchange_modes_extension_0,
      key_share_clienthello_extension_0
   )

   const clientHelloCandidate = unity(
      legacy_version,
      random,
      legacy_session_id_0,
      cipher_suites_0,
      legacy_compression_methods,
      extensions_0
   )
   clientHelloCandidate.groups = supported_groups
   return clientHelloCandidate
   //return sanitizeClientHello(clientHelloCandidate)
}

function sni_extension(...hostNames) {
   const serverNameList = ServerNameList.fromNames(...hostNames)
   const ex = Extension.create(
      ExtensionType.SERVER_NAME,
      serverNameList
   )
   ex.serverNameList = serverNameList;
   return ex;
}

function supported_groups_extension(...groups) {
   const namedGroupList = NamedGroupList.fromGroups(...groups);
   const ex = Extension.create(
      ExtensionType.SUPPORTED_GROUPS,
      namedGroupList
   )
   ex.namedGroupList = namedGroupList
   return ex
}

function signature_algorithms_extension(...signature_algorithms) {
   const signatureSchemeList = SignatureSchemeList.fromSchemes(...signature_algorithms);
   const ex = Extension.create(
      ExtensionType.SIGNATURE_ALGORITHMS,
      signatureSchemeList
   )
   ex.signatureSchemeList = signatureSchemeList
   return ex
}

function supported_versions_extension(...versions) {
   const supported_versions = Versions.fromVersions(...versions);
   const ex = Extension.create(
      ExtensionType.SUPPORTED_VERSIONS,
      supported_versions
   )
   ex.supported_versions = supported_versions;
   return ex;
}

function psk_key_exchange_modes_extension(...modes) {
   const psk_key_exchange_modes = PskKeyExchangeModes.fromModes(...modes);
   const ex = Extension.create(
      ExtensionType.PSK_KEY_EXCHANGE_MODES,
      psk_key_exchange_modes
   );
   ex.psk_key_exchange_modes = psk_key_exchange_modes;
   return ex;
}

function key_share_clienthello_extension(...groups) {
   const key_share_clienthello = KeyShareClientHello.fromGroups(...groups);
   const ex = Extension.create(
      ExtensionType.KEY_SHARE,
      key_share_clienthello
   )
   ex.key_share_clienthello = key_share_clienthello;
   return ex
}

/**
 * ```
 * Extension extensions<8..2^16-1>;
 * ```
 * @param  {...Extension} extensions 
 * @returns 
 */
function extensions(...extensions) {
   return vector16(unity(...extensions))
}

/**
 * ```
 * opaque legacy_session_id<0..32>;
 * ```
 * @param {Uint8Array} session_id 
 */
function legacy_session_id(session_id) {
   return vector8(session_id, { max: 32 })
}

/**
 * ```
 * CipherSuite cipher_suites<2..2^16-2>;
 * ```
 * @param  {...Cipher} ciphers 
 */
function cipher_suites(...ciphers) {
   ciphers = unity(...ciphers.map(e => e.byte));
   return vector(ciphers, { min: 2, max: 2 ** 16 - 2 })
}

function _sanitizeClientHello(data) {
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

   if (offset + extensionsLen > data.length) return null;

   return data.subarray(0, offset + extensionsLen);
}