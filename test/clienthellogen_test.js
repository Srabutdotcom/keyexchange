import { clientHelloGen } from "../src/mod.ts";

const clientHello_test = clientHelloGen("smtp.gmail.com");
const extensions = clientHello_test.extensions;