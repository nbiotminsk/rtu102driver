const DELTA = 0x9e3779b9 >>> 0;

function keyToWordsLE(key16) {
  if (key16.length !== 16) {
    throw new Error("XTEA key must be 16 bytes");
  }
  return [
    key16.readUInt32LE(0),
    key16.readUInt32LE(4),
    key16.readUInt32LE(8),
    key16.readUInt32LE(12),
  ];
}

export function xteaDecryptBlockLE(block8, key16, rounds = 32) {
  if (block8.length !== 8) {
    throw new Error("XTEA block must be 8 bytes");
  }
  if (rounds <= 0) {
    throw new Error("rounds must be positive");
  }

  let v0 = block8.readUInt32LE(0) >>> 0;
  let v1 = block8.readUInt32LE(4) >>> 0;
  const keyWords = keyToWordsLE(key16);

  let sum = Math.imul(DELTA, rounds) >>> 0;
  for (let i = 0; i < rounds; i += 1) {
    v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ ((sum + keyWords[(sum >>> 11) & 3]) >>> 0))) >>> 0;
    sum = (sum - DELTA) >>> 0;
    v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + keyWords[sum & 3]) >>> 0))) >>> 0;
  }

  const out = Buffer.alloc(8);
  out.writeUInt32LE(v0 >>> 0, 0);
  out.writeUInt32LE(v1 >>> 0, 4);
  return out;
}

export function xteaEncryptBlockLE(block8, key16, rounds = 32) {
  if (block8.length !== 8) {
    throw new Error("XTEA block must be 8 bytes");
  }
  if (rounds <= 0) {
    throw new Error("rounds must be positive");
  }

  let v0 = block8.readUInt32LE(0) >>> 0;
  let v1 = block8.readUInt32LE(4) >>> 0;
  const keyWords = keyToWordsLE(key16);

  let sum = 0;
  for (let i = 0; i < rounds; i += 1) {
    v0 = (v0 + ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ ((sum + keyWords[sum & 3]) >>> 0))) >>> 0;
    sum = (sum + DELTA) >>> 0;
    v1 = (v1 + ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ ((sum + keyWords[(sum >>> 11) & 3]) >>> 0))) >>> 0;
  }

  const out = Buffer.alloc(8);
  out.writeUInt32LE(v0 >>> 0, 0);
  out.writeUInt32LE(v1 >>> 0, 4);
  return out;
}

export function xteaDecryptEcbLE(ciphertext, key16, rounds = 32) {
  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error("ciphertext length must be positive and divisible by 8");
  }

  const chunks = [];
  for (let i = 0; i < ciphertext.length; i += 8) {
    chunks.push(xteaDecryptBlockLE(ciphertext.subarray(i, i + 8), key16, rounds));
  }
  return Buffer.concat(chunks);
}

export function xteaEncryptEcbLE(plaintext, key16, rounds = 32) {
  if (plaintext.length === 0 || plaintext.length % 8 !== 0) {
    throw new Error("plaintext length must be positive and divisible by 8");
  }

  const chunks = [];
  for (let i = 0; i < plaintext.length; i += 8) {
    chunks.push(xteaEncryptBlockLE(plaintext.subarray(i, i + 8), key16, rounds));
  }
  return Buffer.concat(chunks);
}
