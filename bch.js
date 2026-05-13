/**
 * BCH 编码 — 纯 JS，与 Python bchlib.BCH(5, 137) 输出完全一致
 *
 * 参数：GF(2^7), prim_poly=137(x^7+x^3+1), t=5, ecc_bits=35
 * 数据：56 bits (7 bytes) → ECC：40 bits (5 bytes, 其中35位有效)
 *
 * 实现方式：预计算 56 个单比特基向量的 ECC，编码时 XOR 组合。
 * 这是从 Python bchlib 实际输出提取的查找表，保证 100% 一致。
 */

// 56 个基向量的 ECC 查找表（数据 LSB 优先：byte0.bit0 = x^0）
// ECC_TABLE[bit_pos] = bchlib.BCH(5,137).encode(data_with_only_bit_pos_set)
const ECC_TABLE = [
  [16, 8, 137, 184, 32],   // bit 0  (byte0.bit0)
  [32, 17, 19, 112, 64],   // bit 1  (byte0.bit1)
  [64, 34, 38, 224, 128],  // bit 2  (byte0.bit2)
  [128, 68, 77, 193, 0],   // bit 3  (byte0.bit3)
  [148, 100, 159, 24, 224],// bit 4  (byte0.bit4)
  [188, 37, 58, 171, 32],  // bit 5  (byte0.bit5)
  [236, 166, 113, 204, 160],// bit 6 (byte0.bit6)
  [77, 160, 231, 3, 160],  // bit 7  (byte0.bit7)
  [14, 10, 92, 160, 192],  // bit 8  (byte1.bit0)
  [28, 20, 185, 65, 128],  // bit 9  (byte1.bit1)
  [56, 41, 114, 131, 0],   // bit 10 (byte1.bit2)
  [112, 82, 229, 6, 0],    // bit 11 (byte1.bit3)
  [224, 165, 202, 12, 0],  // bit 12 (byte1.bit4)
  [85, 167, 144, 130, 224],// bit 13 (byte1.bit5)
  [171, 79, 33, 5, 192],   // bit 14 (byte1.bit6)
  [194, 114, 70, 145, 96], // bit 15 (byte1.bit7)
  [238, 37, 240, 230, 192],// bit 16 (byte2.bit0)
  [72, 167, 229, 87, 96],  // bit 17 (byte2.bit1)
  [145, 79, 202, 174, 192],// bit 18 (byte2.bit2)
  [182, 115, 145, 199, 96],// bit 19 (byte2.bit3)
  [248, 11, 39, 20, 32],   // bit 20 (byte2.bit4)
  [100, 250, 74, 178, 160],// bit 21 (byte2.bit5)
  [201, 244, 149, 101, 64],// bit 22 (byte2.bit6)
  [7, 5, 46, 80, 96],      // bit 23 (byte2.bit7)
  [88, 198, 28, 104, 224], // bit 24 (byte3.bit0)
  [177, 140, 56, 209, 192],// bit 25 (byte3.bit1)
  [247, 244, 117, 57, 96], // bit 26 (byte3.bit2)
  [123, 4, 238, 232, 32],  // bit 27 (byte3.bit3)
  [246, 9, 221, 208, 64],  // bit 28 (byte3.bit4)
  [120, 255, 191, 58, 96], // bit 29 (byte3.bit5)
  [241, 255, 126, 116, 192],// bit 30(byte3.bit6)
  [119, 18, 248, 115, 96], // bit 31 (byte3.bit7)
  [42, 31, 106, 194, 0],   // bit 32 (byte4.bit0)
  [84, 62, 213, 132, 0],   // bit 33 (byte4.bit1)
  [168, 125, 171, 8, 0],   // bit 34 (byte4.bit2)
  [196, 23, 82, 138, 224], // bit 35 (byte4.bit3)
  [28, 194, 161, 143, 32], // bit 36 (byte4.bit4)
  [57, 133, 67, 30, 64],   // bit 37 (byte4.bit5)
  [115, 10, 134, 60, 128], // bit 38 (byte4.bit6)
  [230, 21, 12, 121, 0],   // bit 39 (byte4.bit7)
  [225, 143, 93, 253, 64], // bit 40 (byte5.bit0)
  [87, 242, 191, 96, 96],  // bit 41 (byte5.bit1)
  [175, 229, 126, 192, 192],// bit 42(byte5.bit2)
  [203, 38, 249, 27, 96],  // bit 43 (byte5.bit3)
  [2, 161, 246, 172, 32],  // bit 44 (byte5.bit4)
  [5, 67, 237, 88, 64],    // bit 45 (byte5.bit5)
  [10, 135, 218, 176, 128],// bit 46 (byte5.bit6)
  [21, 15, 181, 97, 0],    // bit 47 (byte5.bit7)
  [148, 236, 4, 154, 224], // bit 48 (byte6.bit0)
  [189, 52, 13, 175, 32],  // bit 49 (byte6.bit1)
  [238, 132, 31, 196, 160],// bit 50 (byte6.bit2)
  [73, 228, 59, 19, 160],  // bit 51 (byte6.bit3)
  [147, 200, 118, 39, 64], // bit 52 (byte6.bit4)
  [179, 124, 232, 212, 96],// bit 53 (byte6.bit5)
  [242, 21, 213, 50, 32],  // bit 54 (byte6.bit6)
  [112, 199, 174, 254, 160],// bit 55(byte6.bit7)
];

/**
 * BCH 编码：对 7 字节数据生成 5 字节 ECC
 * @param {Uint8Array|number[]} data - 7 字节数据
 * @returns {Uint8Array} - 5 字节 ECC
 */
function bchEncode(data) {
  const ecc = new Uint8Array(5);
  for (let bitPos = 0; bitPos < 56; bitPos++) {
    const byteIdx = bitPos >> 3;
    const bitIdx = bitPos & 7;
    if ((data[byteIdx] >> bitIdx) & 1) {
      const row = ECC_TABLE[bitPos];
      for (let j = 0; j < 5; j++) {
        ecc[j] ^= row[j];
      }
    }
  }
  return ecc;
}

/**
 * 完整水印比特编码
 * @param {string} text - 最多 7 字符
 * @returns {number[]} 100 bits (0/1)
 */
function encodeWatermarkBits(text) {
  const encoder = new TextEncoder();
  const utf8 = encoder.encode(text);
  const data = new Uint8Array(7);
  for (let i = 0; i < 7; i++) {
    data[i] = i < utf8.length ? utf8[i] : 0x20;
  }

  const ecc = bchEncode(data);

  // 96 bits = 7 data + 5 ecc（MSB 优先，与 Python format(x,'08b') 一致）
  const bits = [];
  for (let i = 0; i < 7; i++)
    for (let j = 7; j >= 0; j--) bits.push((data[i] >> j) & 1);
  for (let i = 0; i < 5; i++)
    for (let j = 7; j >= 0; j--) bits.push((ecc[i] >> j) & 1);
  while (bits.length < 100) bits.push(0);

  return bits.slice(0, 100);
}

/**
 * 从 100 bits 解码文本（无纠错，直接取数据位）
 * @param {number[]} bits - 100 bits
 * @returns {string} 解码文本
 */
function decodeWatermarkBits(bits) {
  const data = new Uint8Array(7);
  for (let i = 0; i < 7; i++) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | (bits[i * 8 + j] || 0);
    }
    data[i] = byte;
  }
  return new TextDecoder('utf-8').decode(data).replace(/\0/g, '').trim();
}

module.exports = { bchEncode, encodeWatermarkBits, decodeWatermarkBits };
