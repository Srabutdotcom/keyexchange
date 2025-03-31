import { clientHelloRFC8448 } from "./clienthello_test.js";
import { serverHelloGen } from "../src/mod.ts";

const serverHelloMsg = new serverHelloGen(clientHelloRFC8448);
