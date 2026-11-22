import assert from "node:assert/strict";
import {
  BlindCrypto,
  BlindCoreClient,
  BlindSignClient,
  BlindFeedClient,
  BlindMailClient,
  PaymentRequiredError
} from "../js/blindcore-web.js";

function makeMockFetch(handler) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ url, method: init.method || "GET", headers: init.headers || {}, body });
    const res = await handler(url, init, calls.length);
    const status = res.status ?? 200;
    const headersMap = new Map(
      Object.entries(res.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
    );
    const textBody = res.body !== undefined ? JSON.stringify(res.body) : "";
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (k) => headersMap.get(k.toLowerCase()) || null },
      async json() {
        return res.body;
      },
      async text() {
        return textBody;
      }
    };
  };
  fn.calls = calls;
  return fn;
}

async function runTests() {
  // 1. PAD2 power-of-2 sizing and roundtrip
  {
    const sample = "BlindCore zero-knowledge payload";
    const padded = BlindCrypto.pad2(sample, 256);
    assert.equal(padded.length, 256);
    assert.equal(padded.length & (padded.length - 1), 0);
    const unpadded = BlindCrypto.unpad2(padded);
    assert.equal(BlindCrypto.decodeUtf8(unpadded), sample);

    const big = new Uint8Array(300).fill(0x42);
    const paddedBig = BlindCrypto.pad2(big, 256);
    assert.equal(paddedBig.length, 512);
    assert.deepEqual(BlindCrypto.unpad2(paddedBig), big);
  }

  // 2. AES-256-GCM roundtrip + tamper knockout
  {
    const key = BlindCrypto.generateAesKey();
    assert.equal(key.length, 32);
    const msg = "Confidential agreement #42";
    const env = await BlindCrypto.encryptAesGcm(msg, key, { pad: true });
    assert.equal(env.alg, "AES-256-GCM");
    assert.equal(env.pad, "PAD2");

    const plain = await BlindCrypto.decryptAesGcm(env, key);
    assert.equal(BlindCrypto.decodeUtf8(plain), msg);

    // Tamper knockout: flip 1 byte in ciphertext
    const ctBytes = BlindCrypto.fromBase64Url(env.ciphertext);
    ctBytes[0] ^= 0xff;
    const tampered = { ...env, ciphertext: BlindCrypto.toBase64Url(ctBytes) };
    await assert.rejects(() => BlindCrypto.decryptAesGcm(tampered, key));
  }

  // 3. ECDSA P-256 sign/verify + tamper knockout
  {
    const kp = await BlindCrypto.generateSigningKeyPair();
    const payload = "envelope-123:deadbeef";
    const sig = await BlindCrypto.signBytes(kp.privateKey, payload);
    assert.equal(await BlindCrypto.verifyBytes(kp.publicKey, payload, sig), true);
    assert.equal(await BlindCrypto.verifyBytes(kp.publicJwk, payload, sig), true);
    // Tamper knockout
    assert.equal(await BlindCrypto.verifyBytes(kp.publicKey, payload + "!", sig), false);
  }

  // 4. ECDH P-256 Alice/Bob shared secret equality + E2EE DM roundtrip
  {
    const alice = await BlindCrypto.generateEcdhKeyPair();
    const bob = await BlindCrypto.generateEcdhKeyPair();
    const secretAlice = await BlindCrypto.deriveSharedKey(alice.privateKey, bob.publicJwk, "dm-v1");
    const secretBob = await BlindCrypto.deriveSharedKey(bob.privateKey, alice.publicJwk, "dm-v1");
    assert.deepEqual(secretAlice, secretBob);
    assert.equal(secretAlice.length, 32);

    const dmEnv = await BlindCrypto.encryptAesGcm("Meet at 09:00 UTC", secretAlice, { pad: true });
    const dmPlain = BlindCrypto.decodeUtf8(await BlindCrypto.decryptAesGcm(dmEnv, secretBob));
    assert.equal(dmPlain, "Meet at 09:00 UTC");
  }

  // 5. SHA-256 known vector
  {
    const hex = await BlindCrypto.sha256Hex("abc");
    assert.equal(
      hex,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
  }

  // 6. BlindCoreClient + HTTP 402 (x402 v2 / L402 / sBTC) automatic retry hook
  {
    const mockFetch = makeMockFetch((url, init, attempt) => {
      if (attempt === 1) {
        return {
          status: 402,
          headers: {
            "WWW-Authenticate": 'L402 macaroon="mac1", invoice="lnbc1"',
            "X-Payment-Required": "x402-v2"
          },
          body: { x402Version: 2, sbtcAddress: "SP2EXAMPLE" }
        };
      }
      assert.equal(init.headers["X-PAYMENT"], "proof-xyz");
      return { status: 200, body: { rows: [{ id: 1 }] } };
    });

    let seenProtocols = [];
    const core = new BlindCoreClient({
      baseUrl: "https://api.blindcore.io",
      token: "demo-tok",
      fetchImpl: mockFetch,
      onPaymentRequired: async (challenge) => {
        seenProtocols = challenge.protocols;
        return { "X-PAYMENT": "proof-xyz" };
      }
    });

    const res = await core.queryJsonb("events", { type: "click" });
    assert.deepEqual(res, { rows: [{ id: 1 }] });
    assert.deepEqual(seenProtocols, ["x402", "L402", "sBTC"]);
    assert.equal(mockFetch.calls.length, 2);
    assert.equal(mockFetch.calls[0].url, "https://api.blindcore.io/v1/jsonb/query");

    // Without hook, 402 throws PaymentRequiredError
    const noHookFetch = makeMockFetch(() => ({
      status: 402,
      headers: { "X-Payment-Required": "x402-v2" },
      body: { x402Version: 2 }
    }));
    const coreNoHook = new BlindCoreClient({ baseUrl: "https://api.blindcore.io", fetchImpl: noHookFetch });
    await assert.rejects(() => coreNoHook.sklearnMnb({ x: [[1, 2]] }), PaymentRequiredError);
  }

  // 7. BlindSignClient, BlindFeedClient, BlindMailClient request construction
  {
    const mockFetch = makeMockFetch((url) => {
      if (url.endsWith("/v1/sign/envelopes")) return { status: 201, body: { envelope_id: "env_99" } };
      if (url.endsWith("/v1/vault/shares")) return { status: 201, body: { share_id: "sh_77" } };
      return { status: 200, body: { ok: true } };
    });
    const core = new BlindCoreClient({ baseUrl: "https://api.blindcore.io", fetchImpl: mockFetch });
    const sign = new BlindSignClient(core);
    const feed = new BlindFeedClient(core);
    const mail = new BlindMailClient(core);

    const kp = await BlindCrypto.generateSigningKeyPair();
    const envRes = await sign.createEnvelope({
      fileBytes: "NDA contents",
      fileName: "nda.txt",
      title: "NDA",
      signers: ["alice@example.com"],
      signingPrivateKey: kp.privateKey
    });
    assert.equal(envRes.envelopeId, "env_99");
    assert.match(envRes.inviteLink, /^https:\/\/sign\.blindcore\.io\/#env=env_99&k=[A-Za-z0-9_-]+$/);

    await sign.countersignEnvelope({
      envelopeId: "env_99",
      digestHex: envRes.digestHex,
      signingPrivateKey: kp.privateKey,
      signerId: "alice"
    });
    await sign.shredEnvelope("env_99");
    await sign.storeVaultItem({ itemBytes: "secret-key", label: "backup" });
    const shareRes = await sign.createTempShare({ itemId: "item_1", keyBase64Url: envRes.keyBase64Url });
    assert.match(shareRes.shareLink, /#share=sh_77&k=/);

    const aliceEcdh = await BlindCrypto.generateEcdhKeyPair();
    const bobEcdh = await BlindCrypto.generateEcdhKeyPair();
    await feed.registerProfile({
      handle: "alice",
      displayName: "Alice",
      signingPublicJwk: kp.publicJwk,
      ecdhPublicJwk: aliceEcdh.publicJwk
    });
    await feed.createSignedPost({ authorId: "alice", body: "Hello ZK world", signingPrivateKey: kp.privateKey });
    await feed.sendEncryptedDm({
      senderId: "alice",
      recipientId: "bob",
      plaintext: "Secret DM",
      senderEcdhPrivateKey: aliceEcdh.privateKey,
      recipientEcdhPublicKey: bobEcdh.publicJwk
    });
    await feed.createGroup({ name: "Core", creatorId: "alice" });
    await feed.addGroupMember({ groupId: "g1", memberId: "bob", wrappedGroupKey: { alg: "AES-256-GCM", pad: "PAD2", iv: "a", ciphertext: "b" } });
    await feed.removeGroupMemberAndRotate({ groupId: "g1", removeMemberId: "bob", rotatedWrappedKeys: {} });
    await feed.grantTempGroupAccess({ groupId: "g1", guestId: "carol", wrappedGroupKey: { alg: "AES-256-GCM", pad: "PAD2", iv: "a", ciphertext: "b" } });
    await feed.submitDatingSwipe({ actorId: "alice", targetId: "bob", direction: "right" });

    await mail.sendMail({ from: "a@example.com", to: "b@example.com", subject: "Hi", body: "Hello" });
    await mail.requestMagicLink({ email: "a@example.com", redirectUrl: "https://app.example.com" });
    await mail.verifyMagicLink({ token: "tok123" });
    await mail.getDnsRecords("example.com");

    assert.equal(mockFetch.calls.length, 17);
  }

  console.log("ALL_WEB_SDK_TESTS_PASSED (7 suites, 0 failures)");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
