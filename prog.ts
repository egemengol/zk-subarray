import {
  assert,
  Bytes,
  createForeignCurve,
  Crypto,
  Field,
  Struct,
  UInt8,
  ZkProgram,
} from "npm:o1js";
import { DynamicBytes } from "npm:mina-credentials/dynamic";

export function assertSubarray(
  haystack: UInt8[],
  needle: UInt8[],
  sizeNeedle: number,
  offset: number,
  message?: string,
): void {
  for (let i = 0; i < sizeNeedle; i += 1) {
    haystack[offset + i].assertEquals(needle[i], message);
  }
}

export class SubarrayInput extends Struct({
  haystack: Bytes(32),
  needle: Bytes(8),
  offset: Field,
}) {}

export const Subarray = ZkProgram({
  name: "subarray",
  publicInput: SubarrayInput,

  methods: {
    isSubarray: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: SubarrayInput) {
        const sizeNeedle = 8;
        const expectOffset = 4; // incredible foresight at compile time
        assertSubarray(
          inp.haystack.bytes,
          inp.needle.bytes,
          sizeNeedle,
          expectOffset,
          "msg",
        );

        // assertSubarray(
        //   inp.haystack.bytes,
        //   inp.needle.bytes,
        //   sizeNeedle,
        //   inp.offset,
        // );

        // cant do that
      },
    },
  },
});

export class TBS extends DynamicBytes({ maxLength: 500 }) {}
export class PubkeySec1 extends Bytes(65) {}

export class Secp256k1 extends createForeignCurve(
  Crypto.CurveParams.Secp256k1,
) {}

export class PubkeyOfCertificateInput extends Struct({
  tbs: TBS,
  pubkeySec1: PubkeySec1,
  // pubkey: Secp256k1, // somehow fails with 0 != 1 error at program.compile(), could not understand
}) {}

export const PubkeyOfCertificate = ZkProgram({
  name: "pubkey-of-cert",
  publicInput: PubkeyOfCertificateInput,

  methods: {
    isSubarray: {
      privateInputs: [],

      // deno-lint-ignore require-await
      async method(inp: PubkeyOfCertificateInput) {
        assert(Field(2).equals(Field(2)));
      },
    },
  },
});
