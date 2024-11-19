import { assert } from "jsr:@std/assert";
import { decodeBase64 } from "jsr:@std/encoding";
import { secp256k1 } from "npm:@noble/curves/secp256k1";
import { Bytes, Field } from "npm:o1js";

import { decodeBase64toBigInt } from "./direct.ts";
import {
  PubkeyOfCertificate,
  PubkeyOfCertificateInput,
  PubkeySec1,
  Subarray,
  SubarrayInput,
  TBS,
} from "./prog.ts";

Deno.test("testing", async (t) => {
  await Subarray.compile();
  await PubkeyOfCertificate.compile();

  await t.step("subarray", async () => {
    const haystack = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
    const needle = haystack.slice(4, 4 + 8);
    const proof = await Subarray.isSubarray(
      new SubarrayInput({
        haystack: Bytes.from(haystack),
        needle: Bytes.from(needle),
        offset: Field(4),
      }),
    );
    const isValid = await Subarray.verify(proof.proof);
    assert(isValid);
  });

  await t.step("pubkey of cert", async () => {
    const bundle = JSON.parse(Deno.readTextFileSync("./bundle.frodo.json"));
    const tbs = decodeBase64(bundle.cert_local_tbs);

    const x = decodeBase64toBigInt(bundle.cert_local_pubkey.x);
    const y = decodeBase64toBigInt(bundle.cert_local_pubkey.y);
    const pubkey = secp256k1.ProjectivePoint.fromAffine({ x, y });
    const pubkey_sec1 = pubkey.toRawBytes(false);

    const proof = await PubkeyOfCertificate.isSubarray(
      new PubkeyOfCertificateInput({
        tbs: TBS.fromBytes(tbs),
        pubkeySec1: PubkeySec1.from(pubkey_sec1),
        // pubkey: new Secp256k1({ x, y }),
      }),
    );

    const isValid = await PubkeyOfCertificate.verify(proof.proof);
    assert(isValid);
  });
});
