/**
 * BlindCore Zero-Dependency Web SDK (ES Module)
 * Compatible with Browsers, React, Next.js, Vue, Svelte, Cloudflare Workers, and Node.js 22+.
 * Uses standard WebCrypto (crypto.subtle) and Fetch API with zero external dependencies.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function getCrypto() {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error("WebCrypto API (globalThis.crypto.subtle) is required.");
  }
  return globalThis.crypto;
}

function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  }
  if (typeof input === "string") return textEncoder.encode(input);
  throw new TypeError("Expected Uint8Array, ArrayBuffer, or string.");
}

export function toBase64Url(bytes) {
  const arr = toUint8Array(bytes);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < arr.length; i += chunk) {
    binary += String.fromCharCode(...arr.subarray(i, i + chunk));
  }
  const b64 = typeof btoa === "function"
    ? btoa(binary)
    : Buffer.from(arr).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(str) {
  if (typeof str !== "string") throw new TypeError("Expected base64url string.");
  const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  if (typeof atob === "function") {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }
  return new Uint8Array(Buffer.from(padded, "base64"));
}

export function toHex(bytes) {
  const arr = toUint8Array(bytes);
  let out = "";
  for (let i = 0; i < arr.length; i++) {
    out += arr[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function fromHex(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0) {
    throw new TypeError("Invalid hex string.");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Client-side Zero-Knowledge Cryptography primitives (WebCrypto).
 */
export const BlindCrypto = {
  /**
   * Power-of-2 PAD2 padding to hide plaintext length against traffic analysis.
   * Format: [4-byte big-endian original length][payload][zero bytes to power-of-2].
   */
  pad2(input, minBlock = 256) {
    const data = toUint8Array(input);
    const needed = 4 + data.length;
    let size = Math.max(16, minBlock);
    if ((size & (size - 1)) !== 0) {
      size = 1 << Math.ceil(Math.log2(size));
    }
    while (size < needed) {
      size *= 2;
    }
    const out = new Uint8Array(size);
    const view = new DataView(out.buffer);
    view.setUint32(0, data.length, false);
    out.set(data, 4);
    return out;
  },

  /**
   * Removes PAD2 padding and validates length framing.
   */
  unpad2(padded) {
    const arr = toUint8Array(padded);
    if (arr.length < 4) throw new Error("Invalid PAD2 buffer: too short.");
    const view = new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
    const origLen = view.getUint32(0, false);
    if (4 + origLen > arr.length) {
      throw new Error("Invalid PAD2 buffer: length exceeds buffer.");
    }
    return arr.slice(4, 4 + origLen);
  },

  /**
   * Generates a 256-bit random AES-GCM key as raw Uint8Array.
   */
  generateAesKey() {
    const crypto = getCrypto();
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    return key;
  },

  /**
   * Encrypts plaintext with AES-256-GCM and optional PAD2 padding.
   */
  async encryptAesGcm(plaintext, keyBytes, options = {}) {
    const crypto = getCrypto();
    const { pad = true, minBlock = 256, aad = null } = options;
    const rawKey = typeof keyBytes === "string" ? fromBase64Url(keyBytes) : toUint8Array(keyBytes);
    if (rawKey.length !== 32) {
      throw new Error("AES-256-GCM requires a 32-byte key.");
    }
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const payload = pad ? this.pad2(plaintext, minBlock) : toUint8Array(plaintext);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );
    const params = { name: "AES-GCM", iv };
    if (aad !== null && aad !== undefined) {
      params.additionalData = toUint8Array(aad);
    }
    const ctBuf = await crypto.subtle.encrypt(params, cryptoKey, payload);
    return {
      alg: "AES-256-GCM",
      pad: pad ? "PAD2" : "NONE",
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(new Uint8Array(ctBuf))
    };
  },

  /**
   * Decrypts an AES-256-GCM envelope and removes PAD2 padding if present.
   */
  async decryptAesGcm(envelope, keyBytes, options = {}) {
    const crypto = getCrypto();
    const { aad = null } = options;
    const rawKey = typeof keyBytes === "string" ? fromBase64Url(keyBytes) : toUint8Array(keyBytes);
    if (rawKey.length !== 32) {
      throw new Error("AES-256-GCM requires a 32-byte key.");
    }
    const iv = fromBase64Url(envelope.iv);
    const ct = fromBase64Url(envelope.ciphertext);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );
    const params = { name: "AES-GCM", iv };
    if (aad !== null && aad !== undefined) {
      params.additionalData = toUint8Array(aad);
    }
    const plainBuf = await crypto.subtle.decrypt(params, cryptoKey, ct);
    const plainBytes = new Uint8Array(plainBuf);
    return envelope.pad === "PAD2" ? this.unpad2(plainBytes) : plainBytes;
  },

  /**
   * Generates an ECDSA P-256 keypair for digital signatures.
   */
  async generateSigningKeyPair() {
    const crypto = getCrypto();
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicJwk,
      privateJwk
    };
  },

  async importSigningPublicKey(jwk) {
    return getCrypto().subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );
  },

  async importSigningPrivateKey(jwk) {
    return getCrypto().subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );
  },

  /**
   * Signs bytes or string with ECDSA P-256 (SHA-256). Returns base64url signature.
   */
  async signBytes(privateKey, data) {
    const crypto = getCrypto();
    const key = privateKey instanceof CryptoKey
      ? privateKey
      : await this.importSigningPrivateKey(privateKey);
    const sig = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      toUint8Array(data)
    );
    return toBase64Url(new Uint8Array(sig));
  },

  /**
   * Verifies an ECDSA P-256 (SHA-256) base64url signature.
   */
  async verifyBytes(publicKey, data, signatureBase64Url) {
    const crypto = getCrypto();
    const key = publicKey instanceof CryptoKey
      ? publicKey
      : await this.importSigningPublicKey(publicKey);
    const sigBytes = typeof signatureBase64Url === "string"
      ? fromBase64Url(signatureBase64Url)
      : toUint8Array(signatureBase64Url);
    return crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      sigBytes,
      toUint8Array(data)
    );
  },

  /**
   * Generates an ECDH P-256 keypair for E2EE DMs and Group ACL key wrapping.
   */
  async generateEcdhKeyPair() {
    const crypto = getCrypto();
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicJwk,
      privateJwk
    };
  },

  async importEcdhPublicKey(jwk) {
    return getCrypto().subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
  },

  async importEcdhPrivateKey(jwk) {
    return getCrypto().subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
  },

  /**
   * Derives a 32-byte AES-256-GCM shared secret via ECDH P-256 + HKDF-SHA-256.
   */
  async deriveSharedKey(privateKey, peerPublicKey, info = "blindcore-ecdh-v1", salt = null) {
    const crypto = getCrypto();
    const priv = privateKey instanceof CryptoKey
      ? privateKey
      : await this.importEcdhPrivateKey(privateKey);
    const pub = peerPublicKey instanceof CryptoKey
      ? peerPublicKey
      : await this.importEcdhPublicKey(peerPublicKey);
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: pub },
      priv,
      256
    );
    const hkdfKey = await crypto.subtle.importKey(
      "raw",
      sharedBits,
      { name: "HKDF" },
      false,
      ["deriveBits"]
    );
    const saltBytes = salt ? toUint8Array(salt) : new Uint8Array(32);
    const derived = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: saltBytes,
        info: toUint8Array(info)
      },
      hkdfKey,
      256
    );
    return new Uint8Array(derived);
  },

  /**
   * Computes SHA-256 hex digest of bytes or string.
   */
  async sha256Hex(data) {
    const crypto = getCrypto();
    const digest = await crypto.subtle.digest("SHA-256", toUint8Array(data));
    return toHex(new Uint8Array(digest));
  },

  toBase64Url,
  fromBase64Url,
  toHex,
  fromHex,
  encodeUtf8: (s) => textEncoder.encode(s),
  decodeUtf8: (b) => textDecoder.decode(b)
};

export class PaymentRequiredError extends Error {
  constructor(message, challenge) {
    super(message);
    this.name = "PaymentRequiredError";
    this.status = 402;
    this.challenge = challenge;
  }
}

function parsePaymentChallenge(response, body) {
  const wwwAuth = response.headers?.get("www-authenticate") || "";
  const paymentReq =
    response.headers?.get("payment-required") ||
    response.headers?.get("x-payment-required") ||
    "";
  const stacksPayReq = response.headers?.get("x-stacks-payment-required") || "";
  const bodyObj = body && typeof body === "object" ? body : {};
  const extensions =
    bodyObj.extensions && typeof bodyObj.extensions === "object" ? bodyObj.extensions : {};
  const l402Ext =
    extensions.lightning_l402 && typeof extensions.lightning_l402 === "object"
      ? extensions.lightning_l402
      : null;
  const stacksExt =
    extensions.stacks_sbtc && typeof extensions.stacks_sbtc === "object"
      ? extensions.stacks_sbtc
      : null;
  const protocols = [];
  if (paymentReq || bodyObj.x402Version || /x402/i.test(wwwAuth)) protocols.push("x402");
  if (
    /L402/i.test(wwwAuth) ||
    bodyObj.macaroon ||
    bodyObj.invoice ||
    Boolean(l402Ext?.enabled)
  ) {
    protocols.push("L402");
  }
  if (
    stacksPayReq ||
    /sBTC/i.test(wwwAuth) ||
    bodyObj.sbtcAddress ||
    bodyObj.sbtc ||
    Boolean(stacksExt)
  ) {
    protocols.push("sBTC");
  }
  return {
    status: 402,
    protocols,
    wwwAuthenticate: wwwAuth,
    paymentRequired: paymentReq,
    xPaymentRequired: paymentReq,
    stacksPaymentRequired: stacksPayReq,
    body
  };
}

/**
 * Core BlindCore HTTP client with automatic HTTP 402 (x402 v2 / L402 / sBTC) negotiation.
 */
export class BlindCoreClient {
  constructor(options = {}) {
    const {
      baseUrl = "https://api.blindlabs.ai",
      token = null,
      fetchImpl = globalThis.fetch,
      onPaymentRequired = null
    } = options;
    if (typeof fetchImpl !== "function") {
      throw new Error("A Fetch API implementation is required.");
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this.fetchImpl = fetchImpl;
    this.onPaymentRequired = onPaymentRequired;
  }

  async request(path, options = {}) {
    const { method = "GET", body = undefined, headers = {} } = options;
    const url = `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
    const reqHeaders = {
      Accept: "application/json",
      ...headers
    };
    if (this.token && !reqHeaders.Authorization) {
      reqHeaders.Authorization = `Bearer ${this.token}`;
    }
    let payload;
    if (body !== undefined) {
      const explicitCt = reqHeaders["Content-Type"] || reqHeaders["content-type"] || "";
      if (typeof body === "string" && explicitCt && !explicitCt.toLowerCase().includes("application/json")) {
        payload = body;
      } else {
        if (!explicitCt) reqHeaders["Content-Type"] = "application/json";
        payload = JSON.stringify(body);
      }
    }

    const res = await this.fetchImpl(url, { method, headers: reqHeaders, body: payload });
    if (res.status === 402) {
      let challengeBody = null;
      try {
        challengeBody = await res.json();
      } catch {
        challengeBody = null;
      }
      const challenge = parsePaymentChallenge(res, challengeBody);
      if (typeof this.onPaymentRequired === "function") {
        const paymentHeaders = await this.onPaymentRequired(challenge, { url, method, body });
        if (paymentHeaders && typeof paymentHeaders === "object") {
          const retryRes = await this.fetchImpl(url, {
            method,
            headers: { ...reqHeaders, ...paymentHeaders },
            body: payload
          });
          return this._handleResponse(retryRes);
        }
      }
      throw new PaymentRequiredError("HTTP 402 Payment Required", challenge);
    }
    return this._handleResponse(res);
  }

  async _handleResponse(res) {
    const text = await res.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }
    }
    if (!res.ok) {
      const err = new Error(data?.error || `HTTP ${res.status}`);
      err.status = res.status;
      err.body = data;
      throw err;
    }
    return data;
  }

  async health() {
    return this.request("/health", { method: "GET" });
  }

  async pricing() {
    return this.request("/api/v1/pricing", { method: "GET" });
  }

  async queryJson(sql) {
    return this.request("/api/v1/query?format=json", {
      method: "POST",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: String(sql)
    });
  }

  async queryBlindJsonb(payload) {
    return this.request("/api/v1/blind/jsonb/query", {
      method: "POST",
      body: payload
    });
  }

  async ingestBlindJsonb(payload) {
    return this.request("/api/v1/blind/jsonb/ingest", {
      method: "POST",
      body: payload
    });
  }

  async queryBlind(payload) {
    return this.request("/api/v1/blind/query", {
      method: "POST",
      body: payload
    });
  }

  async queryJsonb(collection, filter = {}, options = {}) {
    return this.request("/v1/jsonb/query", {
      method: "POST",
      body: { collection, filter, ...options }
    });
  }

  async ingestJsonb(collection, documents, options = {}) {
    return this.request("/v1/jsonb/ingest", {
      method: "POST",
      body: { collection, documents, ...options }
    });
  }

  async sklearnMnb(payload) {
    return this.request("/v1/ml/sklearn-mnb", {
      method: "POST",
      body: payload
    });
  }
}

/**
 * BlindSign Client: Zero-Knowledge e-Signatures & Encrypted Vault.
 */
export class BlindSignClient {
  constructor(coreClient) {
    this.core = coreClient instanceof BlindCoreClient ? coreClient : new BlindCoreClient(coreClient);
  }

  /**
   * Encrypts file client-side (AES-256-GCM + PAD2), signs digest (ECDSA P-256),
   * uploads ciphertext only, and returns a #env=<id>&k=<key> invite link.
   */
  async createEnvelope({
    fileBytes,
    fileName = "document.bin",
    mimeType = "application/octet-stream",
    title = "Untitled Envelope",
    signers = [],
    signingPrivateKey,
    appOrigin = "https://blindlabs.ai/sign"
  }) {
    const rawBytes = toUint8Array(fileBytes);
    const keyBytes = BlindCrypto.generateAesKey();
    const keyBase64Url = toBase64Url(keyBytes);
    const digestHex = await BlindCrypto.sha256Hex(rawBytes);
    const encrypted = await BlindCrypto.encryptAesGcm(rawBytes, keyBytes, { pad: true });

    let signature = null;
    if (signingPrivateKey) {
      signature = await BlindCrypto.signBytes(signingPrivateKey, `${title}:${digestHex}`);
    }

    const response = await this.core.request("/v1/sign/envelopes", {
      method: "POST",
      body: {
        title,
        file_name: fileName,
        mime_type: mimeType,
        digest_sha256: digestHex,
        signers,
        signature,
        encrypted_blob: encrypted
      }
    });
    const envelopeId = response?.envelope_id || response?.id || "";
    const inviteLink = `${appOrigin.replace(/\/+$/, "")}/#env=${encodeURIComponent(envelopeId)}&k=${keyBase64Url}`;
    return { envelopeId, keyBase64Url, digestHex, inviteLink, response };
  }

  async countersignEnvelope({ envelopeId, digestHex, signingPrivateKey, signerId }) {
    const signature = await BlindCrypto.signBytes(
      signingPrivateKey,
      `${envelopeId}:${digestHex}`
    );
    return this.core.request(`/v1/sign/envelopes/${encodeURIComponent(envelopeId)}/countersign`, {
      method: "POST",
      body: { signer_id: signerId, digest_sha256: digestHex, signature }
    });
  }

  async shredEnvelope(envelopeId, reason = "user_requested") {
    return this.core.request(`/v1/sign/envelopes/${encodeURIComponent(envelopeId)}`, {
      method: "DELETE",
      body: { reason }
    });
  }

  async storeVaultItem({ itemBytes, label = "vault-item", keyBytes = null, metadata = {} }) {
    const key = keyBytes ? toUint8Array(keyBytes) : BlindCrypto.generateAesKey();
    const encrypted = await BlindCrypto.encryptAesGcm(itemBytes, key, { pad: true });
    const response = await this.core.request("/v1/vault/items", {
      method: "POST",
      body: { label, metadata, encrypted_blob: encrypted }
    });
    return { keyBase64Url: toBase64Url(key), response };
  }

  async createTempShare({
    itemId,
    ttlSeconds = 3600,
    maxViews = 1,
    keyBase64Url = "",
    appOrigin = "https://blindlabs.ai/sign"
  }) {
    const response = await this.core.request("/v1/vault/shares", {
      method: "POST",
      body: { item_id: itemId, ttl_seconds: ttlSeconds, max_views: maxViews }
    });
    const shareId = response?.share_id || response?.id || "";
    const shareLink = keyBase64Url
      ? `${appOrigin.replace(/\/+$/, "")}/#share=${encodeURIComponent(shareId)}&k=${keyBase64Url}`
      : `${appOrigin.replace(/\/+$/, "")}/#share=${encodeURIComponent(shareId)}`;
    return { shareId, shareLink, response };
  }
}

/**
 * BlindFeed Client: Signed Posts, E2EE DMs, Group ACLs with Key Rotation, and Blind Dating.
 */
export class BlindFeedClient {
  constructor(coreClient) {
    this.core = coreClient instanceof BlindCoreClient ? coreClient : new BlindCoreClient(coreClient);
  }

  async registerProfile({ handle, displayName, signingPublicJwk, ecdhPublicJwk, bio = "" }) {
    return this.core.request("/v1/feed/profiles", {
      method: "POST",
      body: {
        handle,
        display_name: displayName,
        signing_public_jwk: signingPublicJwk,
        ecdh_public_jwk: ecdhPublicJwk,
        bio
      }
    });
  }

  async createSignedPost({ authorId, body, mediaRefs = [], signingPrivateKey }) {
    const createdAt = new Date().toISOString();
    const canonical = `${authorId}:${createdAt}:${body}`;
    const signature = await BlindCrypto.signBytes(signingPrivateKey, canonical);
    return this.core.request("/v1/feed/posts", {
      method: "POST",
      body: {
        author_id: authorId,
        body,
        media_refs: mediaRefs,
        created_at: createdAt,
        signature
      }
    });
  }

  async sendEncryptedDm({
    senderId,
    recipientId,
    plaintext,
    senderEcdhPrivateKey,
    recipientEcdhPublicKey
  }) {
    const sharedKey = await BlindCrypto.deriveSharedKey(
      senderEcdhPrivateKey,
      recipientEcdhPublicKey,
      "blindcore-dm-v1"
    );
    const encrypted = await BlindCrypto.encryptAesGcm(plaintext, sharedKey, { pad: true });
    return this.core.request("/v1/feed/dms", {
      method: "POST",
      body: {
        sender_id: senderId,
        recipient_id: recipientId,
        encrypted_dm: encrypted
      }
    });
  }

  async createGroup({ name, creatorId, wrappedMemberKeys = {} }) {
    return this.core.request("/v1/feed/groups", {
      method: "POST",
      body: {
        name,
        creator_id: creatorId,
        wrapped_member_keys: wrappedMemberKeys
      }
    });
  }

  async addGroupMember({ groupId, memberId, wrappedGroupKey, role = "member" }) {
    return this.core.request(`/v1/feed/groups/${encodeURIComponent(groupId)}/members`, {
      method: "POST",
      body: {
        member_id: memberId,
        wrapped_group_key: wrappedGroupKey,
        role
      }
    });
  }

  async removeGroupMemberAndRotate({ groupId, removeMemberId, rotatedWrappedKeys }) {
    return this.core.request(`/v1/feed/groups/${encodeURIComponent(groupId)}/rotate`, {
      method: "POST",
      body: {
        remove_member_id: removeMemberId,
        rotated_wrapped_keys: rotatedWrappedKeys
      }
    });
  }

  async grantTempGroupAccess({ groupId, guestId, wrappedGroupKey, ttlSeconds = 3600 }) {
    return this.core.request(`/v1/feed/groups/${encodeURIComponent(groupId)}/temp-access`, {
      method: "POST",
      body: {
        guest_id: guestId,
        wrapped_group_key: wrappedGroupKey,
        ttl_seconds: ttlSeconds
      }
    });
  }

  async submitDatingSwipe({ actorId, targetId, direction, blindToken = null }) {
    return this.core.request("/v1/feed/dating/swipe", {
      method: "POST",
      body: {
        actor_id: actorId,
        target_id: targetId,
        direction,
        blind_token: blindToken
      }
    });
  }
}

/**
 * BlindMail Client: Transactional Mail, Magic Links, and DNS Verification.
 */
export class BlindMailClient {
  constructor(coreClient) {
    this.core = coreClient instanceof BlindCoreClient ? coreClient : new BlindCoreClient(coreClient);
  }

  async sendMail({ from, to, subject, body, encryptedPayload = null }) {
    return this.core.request("/v1/mail/send", {
      method: "POST",
      body: {
        from,
        to,
        subject,
        body,
        encrypted_payload: encryptedPayload
      }
    });
  }

  async requestMagicLink({ email, redirectUrl }) {
    return this.core.request("/v1/mail/magic-link/request", {
      method: "POST",
      body: { email, redirect_url: redirectUrl }
    });
  }

  async verifyMagicLink({ token }) {
    return this.core.request("/v1/mail/magic-link/verify", {
      method: "POST",
      body: { token }
    });
  }

  async getDnsRecords(domain) {
    return this.core.request(`/v1/mail/dns/${encodeURIComponent(domain)}`, {
      method: "GET"
    });
  }
}
