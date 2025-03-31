//@ts-self-types ="../type/clienthellogen.d.ts"
import { ClientHello } from "./clienthello.js";
import { Extension, ExtensionType, NamedGroup, safeuint8array, Uint16 } from "./dep.ts";

const encoder = new TextEncoder

const x25519 = NamedGroup.X25519;
const p256 = NamedGroup.SECP256R1;
const p384 = NamedGroup.SECP384R1;
const p521 = NamedGroup.SECP521R1;
const x448 = NamedGroup.X448;

const groups = new Map([
   [x25519, x25519],
   [p256, p256],
   [p384, p384],
   [p521, p521],
   [x448, x448]
])

function clientHelloProto(
   option = {
      sessionId:Uint8Array.of(0), 
      signatureSchemeList:Uint8Array.of(4, 3, 5, 3, 8, 4, 8, 5, 8, 7, 8, 8, 8, 9, 8, 10)
   }
) {
   const { 
      sessionId = Uint8Array.of(0) , 
      signatureSchemeList = Uint8Array.of(4, 3, 5, 3, 8, 4, 8, 5, 8, 7, 8, 8, 8, 9, 8, 10) 
   } = option; 
   
   const first = Uint8Array.of(
      3, 3,                            // ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
      1, 2, 3, 4, 5, 6, 7, 8,          // opaque Random[32];
      9, 10, 11, 12, 13, 14, 15, 16,
      17, 18, 19, 20, 21, 22, 23, 24,
      25, 26, 27, 28, 29, 30, 31, 32,)
                                       // opaque legacy_session_id<0..32>; pos = 34;  
   const legacy_session_id = sessionId.length > 1 ? Uint8Array.of(sessionId.length, sessionId) : sessionId;

   const mid = Uint8Array.of(
      0, 6,                            // CipherSuite cipher_suites<2..2^16-2>;
      19, 1, 19, 2, 19, 3,
      1, 0,                            // opaque legacy_compression_methods<1..2^8-1>;
      1, 2,                            // extensions length; pos = 45
      0, 43,                           // supported_versions; length:  7
      0, 3,
      2,
      3, 4,
      0, 45,                           // psk_key_exchange_modes; length:  6 
      0, 2,
      1, 1,
      0, 10,                           // supported_groups; length:  16
      0, 12,
      0, 10,
      0, 29, 0, 23, 0, 24, 0, 25, 0, 30,
   )
   const signatureSchemes = signatureSchemeList.length > 0 ? signatureSchemeList : 
   Array.isArray(signatureSchemeList) ? safeuint8array(...signatureSchemeList) : signatureSchemeList;
   
   const signatureSchemeExtension = Uint8Array.of(
      0, 13,                           // signature_algoritms; length:  22
      0, signatureSchemes.length + 2,
      0, signatureSchemes.length,
      ...Array.from(signatureSchemes)
   )

   return safeuint8array(first, legacy_session_id, mid, signatureSchemeExtension)
}

function key_share_clientHello() {
   return Extension.create(
      ExtensionType.KEY_SHARE,
      keyShareClientHello(
         ...groups.keys().map(group => groups.get(group).keyShareEntry())
      )
   )
}

/**
 * struct {
      KeyShareEntry client_shares<0..2^16-1>;
   } KeyShareClientHello;
 * @param  {...Uint8Array} keyShareEntries 
 */
function keyShareClientHello(...keyShareEntries) {
   const keyShareEntriesJoined = safeuint8array(...keyShareEntries);
   const lengthOf = Uint16.fromValue(keyShareEntriesJoined.length);
   return safeuint8array(lengthOf, keyShareEntriesJoined)
}

/**
 * https://www.rfc-editor.org/rfc/rfc6066#section-3
 * struct {
          NameType name_type;
          select (name_type) {
              case host_name: HostName;
          } name;
      } ServerName;

      enum {
          host_name(0), (255)
      } NameType;

      opaque HostName<1..2^16-1>;

      struct {
          ServerName server_name_list<1..2^16-1>
      } ServerNameList;
 * @param  {...any} server 
 */
function serverNameList(...hostNames) {
   const list = []
   for (const hostname of hostNames) {
      const encoded = encoder.encode(hostname);
      const serverName = safeuint8array(0, Uint16.fromValue(encoded.length), encoded);
      list.push(serverName)
   }
   const serverNameJoined = safeuint8array(...list);
   return safeuint8array(Uint16.fromValue(serverNameJoined.length), serverNameJoined)
}

function sni_extension(...hostNames) {
   return Extension.create(
      ExtensionType.SERVER_NAME,
      serverNameList(...hostNames)
   )
}

function clientHelloCore(proto, keyShares, sni) {
   const initial = safeuint8array(proto, keyShares, sni);
   const lengthOfExtensions = Uint16.fromValue(initial.length - 47);
   initial[45] = lengthOfExtensions[0];
   initial[46] = lengthOfExtensions[1];
   crypto.getRandomValues(initial.subarray(2, 34));
   const clientHello = ClientHello.from(initial);
   clientHello.proto = proto;
   clientHello.groups = groups;
   clientHello.keyshares = key_share_clientHello;
   clientHello.sni = sni;
   return clientHello
}

export function clientHelloGen(option = {
   sessionId:Uint8Array.of(0), 
   signatureSchemeList:Uint8Array.of(4, 3, 5, 3, 8, 4, 8, 5, 8, 7, 8, 8, 8, 9, 8, 10),
   serverNames : []
}) {
   const proto = clientHelloProto(option);
   const keyShares = key_share_clientHello();
   
   const { serverNames } = option;
   const sni = serverNames.length > 0 ? sni_extension(...serverNames) : null
   return clientHelloCore(proto, keyShares, ...(sni&&[sni]))
}

export function updateClientHellogroup(clientHello, group) {
   groups.set(group, group);
   const keyShares = key_share_clientHello();
   return clientHelloCore(clientHello.proto, keyShares, clientHello.sni)
}




