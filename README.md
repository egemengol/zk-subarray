For testing, run

```sh
deno test -A
```

For running `direct.ts`, run

```sh
deno run -A direct.ts
```

---

In `PubkeyOfCertificate`, passing a foreign curve failed weirdly, I did the same thing I am doing all the time. Could not figure out.

Doing this with an actual public key with AlmostForeignField coordinates is worthwhile in my opinion,
since I am using the pubkey in a different proof and somehow need to connect the two proofs in the provable context.

---

Will send the bundle for secp521r1 over slack, which is not mocked.
