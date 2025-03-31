import { clientHelloGen } from "../src/mod.ts";

const clientHello_test = clientHelloGen({serverNames : ["smtp.gmail.com"]});
const extensions = clientHello_test.extensions;

const _null = null;