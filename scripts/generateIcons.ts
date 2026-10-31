import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

function createPng(width: number, height: number, r: number, g: number, b: number): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // bit depth
  ihdrData[9] = 2; // color type: truecolor RGB
  ihdrData[10] = 0; // compression
  ihdrData[11] = 0; // filter
  ihdrData[12] = 0; // interlace
  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // Raw image data: filter byte (0) + width * 3 bytes per row
  const rowLength = 1 + width * 3;
  const rawData = Buffer.alloc(height * rowLength);

  for (let y = 0; y < height; y++) {
    const rowOffset = y * rowLength;
    rawData[rowOffset] = 0; // Filter None

    for (let x = 0; x < width; x++) {
      const pxOffset = rowOffset + 1 + x * 3;

      // Draw decorative pattern (wine red with gold border and central diamond)
      const borderDist = Math.min(x, y, width - 1 - x, height - 1 - y);
      const cx = width / 2;
      const cy = height / 2;
      const diamondDist = Math.abs(x - cx) + Math.abs(y - cy);
      const isDiamond = Math.abs(diamondDist - width * 0.22) < 4 || Math.abs(diamondDist - width * 0.12) < 3;
      const isCenter = Math.hypot(x - cx, y - cy) < width * 0.06;

      if (borderDist < 6) {
        // Gold outer border
        rawData[pxOffset] = 254;
        rawData[pxOffset + 1] = 240;
        rawData[pxOffset + 2] = 138;
      } else if (isDiamond || isCenter) {
        // Gold motif
        rawData[pxOffset] = 217;
        rawData[pxOffset + 1] = 119;
        rawData[pxOffset + 2] = 6;
      } else {
        // Wine background gradient
        const factor = 1 - (y / height) * 0.3;
        rawData[pxOffset] = Math.round(r * factor);
        rawData[pxOffset + 1] = Math.round(g * factor);
        rawData[pxOffset + 2] = Math.round(b * factor);
      }
    }
  }

  const compressedData = zlib.deflateSync(rawData);
  const idatChunk = makeChunk('IDAT', compressedData);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function makeChunk(type: string, data: Buffer): Buffer {
  const len = data.length;
  const chunk = Buffer.alloc(12 + len);
  chunk.writeUInt32BE(len, 0);
  chunk.write(type, 4, 4, 'ascii');
  data.copy(chunk, 8);
  const crc = crc32(chunk.subarray(4, 8 + len));
  chunk.writeInt32BE(crc, 8 + len);
  return chunk;
}

function crc32(buf: Buffer): number {
  let crc = -1;
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
  }
  return crc ^ -1;
}

const table = new Int32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  table[i] = c;
}

const pubDir = path.resolve(process.cwd(), 'public');
if (!fs.existsSync(pubDir)) fs.mkdirSync(pubDir, { recursive: true });

fs.writeFileSync(path.join(pubDir, 'pwa-192x192.png'), createPng(192, 192, 100, 31, 37));
fs.writeFileSync(path.join(pubDir, 'pwa-512x512.png'), createPng(512, 512, 100, 31, 37));
fs.writeFileSync(path.join(pubDir, 'apple-touch-icon.png'), createPng(180, 180, 100, 31, 37));
console.log('Generated PWA PNG icons in public/');
