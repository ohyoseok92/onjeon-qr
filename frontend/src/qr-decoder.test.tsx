import { QrReader } from './QrReader';
import { afterEach, expect, it, vi } from 'vitest';
import { signedQrFixture } from './test-fixtures/signed-qr';

afterEach(() => vi.restoreAllMocks());

// Only the canvas pixel transport is supplied by this test. ZXing's actual
// luminance conversion, binarization, detection and decoding run unchanged.
it.each([0, 90, 180, 270])('제품 해독기로 실제 발급 형식의 QR 픽셀을 해독한다 (%s도 회전)', (rotation) => {
  const modules = signedQrFixture.rows.length;
  const scale = 4;
  const size = modules * scale;
  const pixels = new Uint8ClampedArray(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const moduleX = Math.floor(x / scale), moduleY = Math.floor(y / scale);
      const row = rotation === 90 ? modules - 1 - moduleX : rotation === 180 ? modules - 1 - moduleY : rotation === 270 ? moduleX : moduleY;
      const column = rotation === 90 ? moduleY : rotation === 180 ? modules - 1 - moduleX : rotation === 270 ? modules - 1 - moduleY : moduleX;
      const color = signedQrFixture.rows[row][column] === '1' ? 0 : 255;
      const offset = (y * size + x) * 4;
      pixels[offset] = color; pixels[offset + 1] = color; pixels[offset + 2] = color; pixels[offset + 3] = 255;
    }
  }
  const canvas = document.createElement('canvas');
  canvas.width = size; canvas.height = size;
  vi.spyOn(canvas, 'getContext').mockReturnValue({ getImageData: () => ({ data: pixels }) } as unknown as CanvasRenderingContext2D);
  expect(new QrReader().decodeFromCanvas(canvas).getText()).toBe(signedQrFixture.text);
});
