/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeDeterministicCode,
  encryptField,
  decryptField,
  signQrPayload,
  verifyQrSignature,
  processOdiaSpeech,
  evaluateScanFraud,
} from './satyavastraCore';

test('computeDeterministicCode matches deterministic pattern SV-XXXX-XXXX', () => {
  const code = computeDeterministicCode('OR-SMB-2026-9041', 'Niranjan Meher', 112);
  assert.match(code, /^SV-[A-Z2-9]{4}-[A-Z2-9]{4}$/);

  // Must be deterministic
  const code2 = computeDeterministicCode('OR-SMB-2026-9041', 'Niranjan Meher', 112);
  assert.equal(code, code2);

  // Different serial gives different code
  const codeDiff = computeDeterministicCode('OR-SNP-2026-3829', 'Hemalata Meher', 148);
  assert.notEqual(code, codeDiff);
});

test('encryptField and decryptField roundtrip successfully', () => {
  const original = 'Niranjan Meher | Barpali, Bargarh';
  const encrypted = encryptField(original);
  assert.ok(encrypted.startsWith('AES256GCM:'));

  const decrypted = decryptField(encrypted);
  assert.equal(decrypted, original);
});

test('decryptField fails on tampered ciphertext', () => {
  const encrypted = encryptField('Confidential artisan Aadhaar');
  const tampered = encrypted.slice(0, -6) + 'AAAAAA';
  const result = decryptField(tampered);
  assert.ok(result.includes('DECRYPTION_FAILED'));
});

test('signQrPayload and verifyQrSignature validate valid and invalid signatures', () => {
  const serial = 'OR-SMB-2026-9041';
  const exp = Math.floor(Date.now() / 1000) + 120 * 86400;
  const sig = signQrPayload(serial, exp);
  assert.equal(sig.length, 16);

  assert.equal(verifyQrSignature(serial, exp, sig), true);
  assert.equal(verifyQrSignature('OR-SMB-2026-FAKE', exp, sig), false);
});

test('processOdiaSpeech correctly extracts clusters and entities', () => {
  const sambalpurSample = 'ମୁଁ ସମ୍ବଲପୁରରୁ ଆସିଛି ଏବଂ ୧୪୦ ଘଣ୍ଟା ଲାଗିଛି';
  const res = processOdiaSpeech(sambalpurSample);
  assert.equal(res.cluster, 'Sambalpur');
  assert.equal(res.hours, 140);

  const bomkaiSample = 'Bomkai craft from Subarnapur Sonepur';
  const res2 = processOdiaSpeech(bomkaiSample);
  assert.equal(res2.cluster, 'Subarnapur');
  assert.equal(res2.craft, 'Royal Bomkai Sachipar');
});

test('evaluateScanFraud flags velocity burst when 3 scans happen in under 2 minutes', () => {
  const now = new Date();
  const pastScans = [
    { serial: 'OR-SMB-2026-9041', scanned_at: new Date(now.getTime() - 10000), ip_address: '1.1.1.1' },
    { serial: 'OR-SMB-2026-9041', scanned_at: new Date(now.getTime() - 25000), ip_address: '1.1.1.1' },
    { serial: 'OR-SMB-2026-9041', scanned_at: new Date(now.getTime() - 40000), ip_address: '1.1.1.1' },
  ];

  const result = evaluateScanFraud('OR-SMB-2026-9041', pastScans, '1.1.1.1');
  assert.equal(result.isFlagged, true);
  assert.ok(result.reason?.toLowerCase().includes('velocity'));
  assert.ok(result.latencyMs < 50); // High speed evaluation under 50ms
});
