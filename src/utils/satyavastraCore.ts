/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * SatyaVastra Cryptographic Core & Fraud Detection Engine
 */

import crypto from 'node:crypto';

const DEFAULT_KEY_HEX = '73617479617661737472615f7365637572655f6b65795f323032365f33326279';

export function getAesKey(rawKeyHex: string = DEFAULT_KEY_HEX): Buffer {
  try {
    const buf = Buffer.from(rawKeyHex, 'hex');
    if (buf.length === 32) return buf;
  } catch {
    // fallback to sha256
  }
  return crypto.createHash('sha256').update(rawKeyHex).digest();
}

/**
 * Deterministic Authenticity Code Generation (SV-XXXX-XXXX)
 * Mirrors the exact Python algorithm:
 * alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
 * h1: FNV-1a hash with seed 2166136261
 * h2: FNV-1a hash with seed (h1 ^ 0x9e3779b9)
 */
export function computeDeterministicCode(serial: string, weaverName: string, hours: number): string {
  const raw = `${serial}|${weaverName}|${hours}|SV26`;
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

  let h1 = 2166136261;
  for (let i = 0; i < raw.length; i++) {
    h1 = Math.imul(h1 ^ raw.charCodeAt(i), 16777619) >>> 0;
  }

  let h2 = (h1 ^ 0x9e3779b9) >>> 0;
  for (let i = 0; i < raw.length; i++) {
    h2 = Math.imul(h2 ^ raw.charCodeAt(i), 16777619) >>> 0;
  }

  let part1 = '';
  let part2 = '';
  for (let i = 0; i < 4; i++) {
    part1 += alphabet[(h1 >>> (i * 5)) & 31];
    part2 += alphabet[(h2 >>> (i * 5)) & 31];
  }
  return `SV-${part1}-${part2}`;
}

/**
 * AES-256-GCM field encryption for DPDP Act 2023 compliance
 * Output format: AES256GCM:<base64(12-byte-nonce + ciphertext + 16-byte-authTag)>
 */
export function encryptField(plainText: string, keyHex: string = DEFAULT_KEY_HEX): string {
  if (!plainText) return '';
  const key = getAesKey(keyHex);
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const packed = Buffer.concat([nonce, encrypted, authTag]);
  return 'AES256GCM:' + packed.toString('base64');
}

export function decryptField(encryptedStr: string, keyHex: string = DEFAULT_KEY_HEX): string {
  if (!encryptedStr || !encryptedStr.startsWith('AES256GCM:')) {
    return encryptedStr || '';
  }
  try {
    const rawB64 = encryptedStr.replace('AES256GCM:', '');
    const packed = Buffer.from(rawB64, 'base64');
    if (packed.length < 28) return '[DECRYPTION_FAILED: Invalid length]';
    const nonce = packed.subarray(0, 12);
    const authTag = packed.subarray(packed.length - 16);
    const ciphertext = packed.subarray(12, packed.length - 16);
    const key = getAesKey(keyHex);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (err: any) {
    return `[DECRYPTION_FAILED: ${err.message || 'Cipher error'}]`;
  }
}

/**
 * Server signature for QR tags
 */
export function signQrPayload(serial: string, expiresAtTs: number, keyHex: string = DEFAULT_KEY_HEX): string {
  const message = `${serial}|${expiresAtTs}`;
  const key = getAesKey(keyHex);
  return crypto.createHmac('sha256', key).update(message).digest('hex').substring(0, 16);
}

export function verifyQrSignature(serial: string, expiresAtTs: number, signature: string, keyHex: string = DEFAULT_KEY_HEX): boolean {
  const expected = signQrPayload(serial, expiresAtTs, keyHex);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

/**
 * Odia Voice Processing
 */
export interface ExtractedVoiceData {
  cluster: string;
  village: string;
  craft: string;
  hours: number;
  ties: string;
  material: string;
  motif: string;
  years: number;
  story: string;
}

export function processOdiaSpeech(transcriptText: string): ExtractedVoiceData {
  const text = transcriptText.trim();
  const extracted: ExtractedVoiceData = {
    cluster: 'Bargarh',
    village: 'Barpali',
    craft: 'Sambalpuri Pasapali Bandha',
    hours: 120,
    ties: '4,800 ties',
    material: 'Pure Mulberry Silk',
    motif: 'Pasapali & Shankha',
    years: 25,
    story: text,
  };

  const textLower = text.toLowerCase();
  if (text.includes('ବୋମକାଇ') || text.includes('ସୁବର୍ଣ୍ଣପୁର') || textLower.includes('bomkai')) {
    extracted.cluster = 'Subarnapur';
    extracted.village = 'Sonepur';
    extracted.craft = 'Royal Bomkai Sachipar';
    extracted.material = 'Mulberry Silk & Zari';
    extracted.motif = 'Mayura (Peacock) & Padma';
    extracted.hours = 148;
    extracted.ties = '6,200 ties';
  } else if (text.includes('କୋଟପାଡ଼') || text.includes('କୋରାପୁଟ') || textLower.includes('kotpad')) {
    extracted.cluster = 'Koraput';
    extracted.village = 'Kotpad';
    extracted.craft = 'Kotpad Aal-Dyed Organic Weave';
    extracted.material = 'Handspun Organic Cotton';
    extracted.motif = 'Machha (Fish) & Chauka';
    extracted.hours = 180;
    extracted.ties = '2,400 ties';
  } else if (text.includes('ସମ୍ବଲପୁର') || textLower.includes('sambalpur')) {
    extracted.cluster = 'Sambalpur';
    extracted.village = 'Sambalpur';
    extracted.craft = 'Sambalpuri Ikat Bandha';
    extracted.material = 'Mulberry Silk';
    extracted.motif = 'Chakra & Phula';
    extracted.hours = 126;
    extracted.ties = '5,400 ties';
  }

  // Convert Odia numerals (୦-୯) to Arabic numerals (0-9)
  const odiaDigits: Record<string, string> = {
    '୦': '0', '୧': '1', '୨': '2', '୩': '3', '୪': '4',
    '୫': '5', '୬': '6', '୭': '7', '୮': '8', '୯': '9'
  };
  const normalizedText = text.replace(/[୦-୯]/g, (ch) => odiaDigits[ch] || ch);

  // Extract numeric hours if mentioned (20-500)
  const tokens = normalizedText.split(/\s+/);
  for (const token of tokens) {
    const clean = token.replace(/\D/g, '');
    if (clean) {
      const num = parseInt(clean, 10);
      if (num >= 20 && num <= 500) {
        extracted.hours = num;
      }
    }
  }

  return extracted;
}

/**
 * Fraud Detection Engine
 */
export interface ScanRecord {
  serial: string;
  scanned_at: string | Date;
  ip_address?: string;
}

export function evaluateScanFraud(
  serial: string,
  recentScans: ScanRecord[],
  currentIp: string
): { isFlagged: boolean; reason: string | null; latencyMs: number } {
  const start = performance.now();
  let isFlagged = false;
  let reason: string | null = null;
  const now = Date.now();
  const twoMinAgo = now - 2 * 60 * 1000;
  const oneHourAgo = now - 60 * 60 * 1000;

  const relevant = recentScans.filter((s) => s.serial === serial);

  // Check burst velocity in last 2 mins (>= 3 scans)
  const burstCount = relevant.filter((s) => {
    const ts = new Date(s.scanned_at).getTime();
    return ts >= twoMinAgo;
  }).length;

  if (burstCount >= 3) {
    isFlagged = true;
    reason = 'High velocity anomaly: Scan bursts indicate physical tag duplication';
  }

  // Check distributed IP attacks in last hour (>= 4 disparate IPs)
  const ips = new Set<string>();
  if (currentIp) ips.add(currentIp);
  for (const s of relevant) {
    const ts = new Date(s.scanned_at).getTime();
    if (ts >= oneHourAgo && s.ip_address) {
      ips.add(s.ip_address);
    }
  }

  if (ips.size >= 4) {
    isFlagged = true;
    reason = `Distributed scan attack detected across ${ips.size} disparate networks`;
  }

  const latencyMs = Number((performance.now() - start).toFixed(2));
  return { isFlagged, reason, latencyMs };
}
