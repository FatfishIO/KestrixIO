/**
 * Kestrix Fingerprint & Secret Protection Module
 * Enforces Security Rule #1 (never store or expose raw secret) and Rule #9 (chống path traversal).
 */

// Pure TypeScript SHA-256 implementation for deterministic, environment-agnostic hashing
export function sha256(ascii: string): string {
  function rightRotate(value: number, amount: number) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const words: number[] = [];
  const asciiBitLength = ascii.length * 8;
  let i = 0;
  let j = 0;

  let hash: number[] = [];
  let k: number[] = [];
  let primeCounter = 0;

  const isComposite: Record<number, boolean> = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 300; i += candidate) {
        isComposite[i] = true;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  ascii += '\x80';
  while ((ascii.length % 64) - 56 !== 0) ascii += '\x00';
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words.length] = (asciiBitLength / maxWord) | 0;
  words[words.length] = asciiBitLength;

  for (j = 0; j < words.length; ) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];

      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp1 =
        hash[7] +
        (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) +
        ch +
        k[i] +
        (w[i] =
          i < 16
            ? w[i]
            : (w[i - 16] + s0 + w[i - 7] + s1) | 0);
      const temp2 =
        (rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) +
        maj;

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }

    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }

  let result = '';
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

/**
 * Normalize and sanitize file paths:
 * Prevents path traversal (Rule #9), normalizes slashes, strips leading ./ and ../
 */
export function normalizePath(filePath: string): string {
  if (!filePath) return '';
  // Convert backslashes
  let cleaned = filePath.replace(/\\/g, '/');

  // Strip initial slashes
  cleaned = cleaned.replace(/^\/+/, '');

  // Split and resolve path segments safely
  const segments = cleaned.split('/');
  const stack: string[] = [];

  for (const seg of segments) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (stack.length > 0) {
        stack.pop();
      }
      // If stack is empty, ignore .. to strictly avoid traversing out of project
    } else {
      stack.push(seg);
    }
  }

  return stack.join('/');
}

/**
 * Mask raw secret (Rule #1):
 * Never stores or exposes raw secret.
 * Returns SHA-256 hash and masked suffix (e.g. "****3456").
 */
export function maskSecret(rawSecret: string): { hash: string; masked: string } {
  const hash = sha256(rawSecret);
  if (!rawSecret || rawSecret.length <= 4) {
    return { hash, masked: '****' };
  }
  const last4 = rawSecret.slice(-4);
  return { hash, masked: `****${last4}` };
}

/**
 * SAST Fingerprint:
 * hash of rule_id + normalized_path + normalized_snippet
 * (Does NOT use line numbers so code movement does not fragment the finding)
 */
export function computeSastFingerprint(
  ruleId: string,
  filePath: string,
  codeSnippet: string
): string {
  const normPath = normalizePath(filePath);
  // Normalize whitespace in snippet
  const normSnippet = codeSnippet.trim().replace(/\s+/g, ' ');
  return sha256(`sast:${ruleId.trim()}:${normPath}:${normSnippet}`);
}

/**
 * Secret Fingerprint:
 * hash of rule_id + normalized_path + sha256(secret)
 * Returns fingerprint along with masked version and secret hash.
 */
export function computeSecretFingerprint(
  ruleId: string,
  filePath: string,
  rawSecret: string
): { fingerprint: string; secretHash: string; secretMasked: string } {
  const normPath = normalizePath(filePath);
  const { hash: secretHash, masked: secretMasked } = maskSecret(rawSecret);
  const fingerprint = sha256(`secret:${ruleId.trim()}:${normPath}:${secretHash}`);
  return { fingerprint, secretHash, secretMasked };
}

/**
 * Dependency Fingerprint:
 * hash of ecosystem + package + vuln_id + normalized manifest_path
 * (Does NOT include package version so upgrading version without full fix keeps finding identity)
 */
export function computeDependencyFingerprint(
  ecosystem: string,
  packageName: string,
  vulnId: string,
  manifestPath: string
): string {
  const normPath = normalizePath(manifestPath);
  return sha256(
    `dep:${ecosystem.toLowerCase().trim()}:${packageName.toLowerCase().trim()}:${vulnId.trim()}:${normPath}`
  );
}
