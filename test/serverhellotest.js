import { HexaDecimal } from "../src/dep.ts";
import { ServerHello } from "../type/serverhello.js";
import { assertEquals } from "@std/assert"
import { serverHelloGen } from "../type/serverhellogen.js";
import { clientHelloRFC8448 } from "./clienthellotest.js";

Deno.test("ServerHello", ()=>{
   const serverHello = HexaDecimal.fromString(`03 03 a6
      af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14
      34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00
      1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6
      cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`).byte
   
   const serverHelloBack = ServerHello.from(serverHello);
   
   assertEquals(serverHello.toString(), serverHelloBack.toString());

})

const serverHello = HexaDecimal.fromString(`03 03 a6
   af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14
   34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00
   1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6
   cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04`).byte

const serverHelloBack = ServerHello.from(serverHello);

const serverHelloFromClientHello = serverHelloGen(clientHelloRFC8448);

