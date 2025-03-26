//@ts-self-types = "../type/serverhellogen.d.ts"
import { ClientHello } from "./clienthello.js";
import { Cipher, Extension, ExtensionType, NamedGroup, safeuint8array, Uint16, Version } from "./dep.ts";
import { ServerHello } from "./mod.ts";

const preferredCiphers = new Set([
   Cipher.AES_128_GCM_SHA256,
   Cipher.AES_256_GCM_SHA384,
   Cipher.CHACHA20_POLY1305_SHA256
])

const preferredGroup = new Set([
   NamedGroup.X25519,
   NamedGroup.SECP256R1,
   NamedGroup.SECP384R1,
   NamedGroup.SECP521R1,
   NamedGroup.X448
])


export function serverHelloGen(clientHello) {
   clientHello = (clientHello instanceof ClientHello) ? clientHello : ClientHello.from(clientHello)
   const { legacy_session_id, ciphers, groups } = clientHello

   const group = preferredGroup.intersection(new Set([...groups.keys()])).values().next().value;
   // legacy_version = 0x0303;    /* TLS v1.2 */
   const version = Version.legacy.byte;
   // should no match group then it is HRR with standard random below.
   const random = group ? crypto.getRandomValues(new Uint8Array(32)) :
      Uint8Array.of(207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156)

   // legacy_session_id_echo<0..32>;  
   const legacy_session_id_echo = legacy_session_id ? Uint8Array.of(legacy_session_id.length, legacy_session_id) : Uint8Array.of(0);
   const cipher = preferredCiphers.intersection(ciphers).values().next().value;
   const legacy_compression_method = 0

   const selected_version_extension = Uint8Array.of(0, 43, 0, 2, 3, 3)
   const keyshare_serverHello = keyshare_extension(group);

   const serverHello = safeuint8array(
      version,
      random,
      legacy_session_id_echo,
      cipher,
      legacy_compression_method,
      Uint16.fromValue(6 + keyshare_serverHello.length),
      selected_version_extension,
      keyshare_serverHello
   )
   serverHello.group = group;
   return ServerHello.from(serverHello)
}

const selected_version_extension = Extension.create(
   ExtensionType.SUPPORTED_VERSIONS,
   Uint8Array.of(3, 3)
)
console.log("version", selected_version_extension.toString())

function keyshare_extension(group) {
   if (group) {
      return Extension.create(
         ExtensionType.KEY_SHARE,
         group.keyShareEntry()
      )
   }
   return Extension.create(
      ExtensionType.KEY_SHARE,
      NamedGroup.X25519.byte
   )
}

const _keyshare = keyshare_extension(/* NamedGroup.X25519 */);
console.log("keyshare", _keyshare.toString())
