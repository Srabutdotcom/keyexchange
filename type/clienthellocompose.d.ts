import { Cipher, NamedGroup, PskKeyExchangeMode, SignatureScheme, Version } from "../src/dep.ts";

interface ClientHelloOptions {
   legacy_version?: Uint8Array;
   random?: Uint8Array;
   session_id?: Uint8Array;
   legacy_session_id?: Uint8Array;
   ciphers?: Cipher[];
   legacy_compression_methods?: Uint8Array;
   supported_versions?: Version[];
   psk_key_exchange_modes?: PskKeyExchangeMode[];
   supported_groups?: NamedGroup[];
   signature_algorithms?: SignatureScheme[];
   server_names?: string[];
 }
 
 export declare function clientHelloCompose(option?: ClientHelloOptions): Uint8Array;
 