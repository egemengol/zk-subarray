import { decodeBase64, decodeHex, encodeHex } from "jsr:@std/encoding";
import { p521 } from "npm:@noble/curves/p521";

export function decodeBase64toBigInt(s: string): bigint {
  return BigInt("0x" + encodeHex(decodeBase64(s)));
}

export function findSubarray(haystack: Uint8Array, needle: Uint8Array): number {
  return haystack.findIndex((_, i) =>
    haystack.slice(i, i + needle.length).every((v, j) => v === needle[j])
  );
}

function findWithHeader(tbs: Uint8Array, pubkey_sec1: Uint8Array): number {
  /*
  subjectPublicKeyInfo SubjectPublicKeyInfo SEQUENCE (2 elem)
      algorithm AlgorithmIdentifier SEQUENCE (2 elem)
          algorithm OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
          parameters ANY OBJECT IDENTIFIER 1.3.132.0.10 secp256k1 (SECG (Certicom) named elliptic curve)
      subjectPublicKey BIT STRING (520 bit) 0000010010001110100001000011000010010011100011111110001001110101000000…
  */
  /*
  Public key is encoded as sec1 *in* the bitstring
  The *header* is the same for all secp256k1 starting from SubjectPublicKeyInfo up until the bitstring contents, including the bitstring length.
  */
  const subjectPublicKeyInfoHeader = decodeHex(
    "3056301006072A8648CE3D020106052B8104000A0342",
  );

  const pubkeyWithHeader = Array.from(subjectPublicKeyInfoHeader).concat(
    [
      0x00, // This zero byte is from asn1 BITSTRING encoding, means that there are no unused bits, for this pubkey.
    ].concat(Array.from(pubkey_sec1)),
  );

  const index = findSubarray(tbs, Uint8Array.from(pubkeyWithHeader));
  console.log(
    "found with header at",
    index,
    "where pubkey actually starts at",
    index + subjectPublicKeyInfoHeader.length + 1,
  );
  return index;
}

// Instead of all the header matching as above, lets just try to find the pubkey encoding in the tbsCertificate
// and bet on the unlikeliness of a malicious and invalid tbsCertificate to have the exact 520 bits
// that is also signed by one of the known CSCA authorities.
function findWithoutHeader(tbs: Uint8Array, pubkey_sec1: Uint8Array): number {
  const index = findSubarray(tbs, pubkey_sec1);
  console.log(
    "found without header at",
    index,
  );
  return index;
}

if (import.meta.main) {
  const bundle = JSON.parse(Deno.readTextFileSync("./bundle.halit.json"));
  const tbs = decodeBase64(bundle.cert_local_tbs);

  const x = decodeBase64toBigInt(bundle.cert_local_pubkey.x);
  const y = decodeBase64toBigInt(bundle.cert_local_pubkey.y);
  // const pubkey = secp256k1.ProjectivePoint.fromAffine({ x, y });
  const pubkey = p521.ProjectivePoint.fromAffine({ x, y });
  const pubkey_sec1 = pubkey.toRawBytes(false);

  findWithHeader(tbs, pubkey_sec1);
  findWithoutHeader(tbs, pubkey_sec1);

  console.log("x:", x.toString(16));
  console.log("y:", y.toString(16));
  console.log("sec1:", encodeHex(pubkey_sec1));
  // which is [0x04, ...x, ...y] for secp256k1
  // [0x04, 0, ...x, 0, ...y] for secp521r1 for padding to a full byte.
}
