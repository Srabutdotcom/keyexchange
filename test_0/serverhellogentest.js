import { clientHelloRFC8448 } from "../test/clienthellotest.js";
import { serverHelloGen } from "../src/mod.ts";

const serverHelloMsg = new serverHelloGen(clientHelloRFC8448);
