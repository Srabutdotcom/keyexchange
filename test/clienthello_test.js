import { ClientHello, Cipher_suites } from "../src/clienthello.js";
import { Cipher, ExtensionType, HexaDecimal, KeyShareServerHello, NamedGroup, NamedGroupList, PskKeyExchangeModes, SupportedVersions } from "../src/dep.ts"
import { assertEquals } from "@std/assert"
import { selectFirstMatch, selectKeyExchange } from "../src/utils.js";
import { ServerHello } from "../src/serverhello.js";
import { Selected_version, Supported_signature_algorithms } from "@tls/extension";

Deno.test("Cipher_suites", () => {
   const test = new Cipher_suites(Cipher.AES_128_GCM_SHA256, Cipher.AES_256_GCM_SHA384);
   const back = Cipher_suites.from(test);
   assertEquals(test, back)
})

Deno.test("ClientHello", () => {
   const clientHello = ClientHello.fromServerName('localhost');
   const clientHelloback = ClientHello.from(clientHello)
   assertEquals(clientHello, clientHelloback)
   // from RFC 8448 sample
   const clientHelloRFC8448 = HexaDecimal.fromString(`03 03 cb
      34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
      ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
      00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
      00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
      01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
      e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
      54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
      04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
      01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`).byte

   const clientHelloRFC8448back = ClientHello.from(clientHelloRFC8448)
   assertEquals(clientHelloRFC8448.toString(), clientHelloRFC8448back.toString())
})


// RENEGOTIATION_INFO
// SESSION_TICKET
// RECORD_SIZE_LIMIT

// from RFC 8448 sample
const clientHelloRFC8448 = HexaDecimal.fromString(`03 03 cb
   34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
   ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
   00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
   00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
   01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
   e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
   54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
   04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
   01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`).byte

const clientHelloRFC8448back = ClientHello.from(clientHelloRFC8448)

const test = ServerHello.fromClient_hello(clientHelloRFC8448back)


const clientHello = ClientHello.fromServerName('localhost');
const clientHelloback = ClientHello.from(clientHello)

const supportedGroup = ExtensionType.SUPPORTED_GROUPS.extension(NamedGroupList.default());
const signatureAlgorithms = ExtensionType.SIGNATURE_ALGORITHMS.extension(Supported_signature_algorithms.default());
const pskKeyExchangeModes = ExtensionType.PSK_KEY_EXCHANGE_MODES.extension(PskKeyExchangeModes.default())
const supportedVersions = ExtensionType.SUPPORTED_VERSIONS.extension(SupportedVersions.forClient_hello())

debugger;