export type ByteInput = Uint8Array | ArrayBuffer | ArrayBufferView | string;

export interface EncryptedEnvelope {
  alg: "AES-256-GCM";
  pad: "PAD2" | "NONE";
  iv: string;
  ciphertext: string;
}

export interface AesGcmOptions {
  pad?: boolean;
  minBlock?: number;
  aad?: ByteInput | null;
}

export interface ExportedKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
}

export interface PaymentChallenge {
  status: 402;
  protocols: Array<"x402" | "L402" | "sBTC">;
  wwwAuthenticate: string;
  xPaymentRequired: string;
  body: unknown;
}

export type PaymentRequiredHandler = (
  challenge: PaymentChallenge,
  context: { url: string; method: string; body?: unknown }
) => Promise<Record<string, string> | null | undefined> | Record<string, string> | null | undefined;

export interface BlindCoreClientOptions {
  baseUrl?: string;
  token?: string | null;
  fetchImpl?: typeof fetch;
  onPaymentRequired?: PaymentRequiredHandler | null;
}

export function toBase64Url(bytes: ByteInput): string;
export function fromBase64Url(str: string): Uint8Array;
export function toHex(bytes: ByteInput): string;
export function fromHex(hex: string): Uint8Array;

export const BlindCrypto: {
  pad2(input: ByteInput, minBlock?: number): Uint8Array;
  unpad2(padded: ByteInput): Uint8Array;
  generateAesKey(): Uint8Array;
  encryptAesGcm(
    plaintext: ByteInput,
    keyBytes: ByteInput | string,
    options?: AesGcmOptions
  ): Promise<EncryptedEnvelope>;
  decryptAesGcm(
    envelope: EncryptedEnvelope,
    keyBytes: ByteInput | string,
    options?: { aad?: ByteInput | null }
  ): Promise<Uint8Array>;
  generateSigningKeyPair(): Promise<ExportedKeyPair>;
  importSigningPublicKey(jwk: JsonWebKey): Promise<CryptoKey>;
  importSigningPrivateKey(jwk: JsonWebKey): Promise<CryptoKey>;
  signBytes(privateKey: CryptoKey | JsonWebKey, data: ByteInput): Promise<string>;
  verifyBytes(
    publicKey: CryptoKey | JsonWebKey,
    data: ByteInput,
    signatureBase64Url: string | Uint8Array
  ): Promise<boolean>;
  generateEcdhKeyPair(): Promise<ExportedKeyPair>;
  importEcdhPublicKey(jwk: JsonWebKey): Promise<CryptoKey>;
  importEcdhPrivateKey(jwk: JsonWebKey): Promise<CryptoKey>;
  deriveSharedKey(
    privateKey: CryptoKey | JsonWebKey,
    peerPublicKey: CryptoKey | JsonWebKey,
    info?: string,
    salt?: ByteInput | null
  ): Promise<Uint8Array>;
  sha256Hex(data: ByteInput): Promise<string>;
  toBase64Url(bytes: ByteInput): string;
  fromBase64Url(str: string): Uint8Array;
  toHex(bytes: ByteInput): string;
  fromHex(hex: string): Uint8Array;
  encodeUtf8(s: string): Uint8Array;
  decodeUtf8(b: Uint8Array): string;
};

export class PaymentRequiredError extends Error {
  readonly status: 402;
  readonly challenge: PaymentChallenge;
  constructor(message: string, challenge: PaymentChallenge);
}

export class BlindCoreClient {
  baseUrl: string;
  token: string | null;
  fetchImpl: typeof fetch;
  onPaymentRequired: PaymentRequiredHandler | null;

  constructor(options?: BlindCoreClientOptions);
  request<T = unknown>(
    path: string,
    options?: { method?: string; body?: unknown; headers?: Record<string, string> }
  ): Promise<T>;
  queryJsonb<T = unknown>(
    collection: string,
    filter?: Record<string, unknown>,
    options?: Record<string, unknown>
  ): Promise<T>;
  ingestJsonb<T = unknown>(
    collection: string,
    documents: Array<Record<string, unknown>>,
    options?: Record<string, unknown>
  ): Promise<T>;
  sklearnMnb<T = unknown>(payload: Record<string, unknown>): Promise<T>;
}

export class BlindSignClient {
  core: BlindCoreClient;
  constructor(coreClient: BlindCoreClient | BlindCoreClientOptions);

  createEnvelope(params: {
    fileBytes: ByteInput;
    fileName?: string;
    mimeType?: string;
    title?: string;
    signers?: string[];
    signingPrivateKey?: CryptoKey | JsonWebKey;
    appOrigin?: string;
  }): Promise<{
    envelopeId: string;
    keyBase64Url: string;
    digestHex: string;
    inviteLink: string;
    response: unknown;
  }>;

  countersignEnvelope(params: {
    envelopeId: string;
    digestHex: string;
    signingPrivateKey: CryptoKey | JsonWebKey;
    signerId: string;
  }): Promise<unknown>;

  shredEnvelope(envelopeId: string, reason?: string): Promise<unknown>;

  storeVaultItem(params: {
    itemBytes: ByteInput;
    label?: string;
    keyBytes?: ByteInput | null;
    metadata?: Record<string, unknown>;
  }): Promise<{ keyBase64Url: string; response: unknown }>;

  createTempShare(params: {
    itemId: string;
    ttlSeconds?: number;
    maxViews?: number;
    keyBase64Url?: string;
    appOrigin?: string;
  }): Promise<{ shareId: string; shareLink: string; response: unknown }>;
}

export class BlindFeedClient {
  core: BlindCoreClient;
  constructor(coreClient: BlindCoreClient | BlindCoreClientOptions);

  registerProfile(params: {
    handle: string;
    displayName: string;
    signingPublicJwk: JsonWebKey;
    ecdhPublicJwk: JsonWebKey;
    bio?: string;
  }): Promise<unknown>;

  createSignedPost(params: {
    authorId: string;
    body: string;
    mediaRefs?: string[];
    signingPrivateKey: CryptoKey | JsonWebKey;
  }): Promise<unknown>;

  sendEncryptedDm(params: {
    senderId: string;
    recipientId: string;
    plaintext: ByteInput;
    senderEcdhPrivateKey: CryptoKey | JsonWebKey;
    recipientEcdhPublicKey: CryptoKey | JsonWebKey;
  }): Promise<unknown>;

  createGroup(params: {
    name: string;
    creatorId: string;
    wrappedMemberKeys?: Record<string, EncryptedEnvelope>;
  }): Promise<unknown>;

  addGroupMember(params: {
    groupId: string;
    memberId: string;
    wrappedGroupKey: EncryptedEnvelope;
    role?: string;
  }): Promise<unknown>;

  removeGroupMemberAndRotate(params: {
    groupId: string;
    removeMemberId: string;
    rotatedWrappedKeys: Record<string, EncryptedEnvelope>;
  }): Promise<unknown>;

  grantTempGroupAccess(params: {
    groupId: string;
    guestId: string;
    wrappedGroupKey: EncryptedEnvelope;
    ttlSeconds?: number;
  }): Promise<unknown>;

  submitDatingSwipe(params: {
    actorId: string;
    targetId: string;
    direction: "left" | "right" | "super";
    blindToken?: string | null;
  }): Promise<unknown>;
}

export class BlindMailClient {
  core: BlindCoreClient;
  constructor(coreClient: BlindCoreClient | BlindCoreClientOptions);

  sendMail(params: {
    from: string;
    to: string | string[];
    subject: string;
    body: string;
    encryptedPayload?: EncryptedEnvelope | null;
  }): Promise<unknown>;

  requestMagicLink(params: { email: string; redirectUrl: string }): Promise<unknown>;
  verifyMagicLink(params: { token: string }): Promise<unknown>;
  getDnsRecords(domain: string): Promise<unknown>;
}
