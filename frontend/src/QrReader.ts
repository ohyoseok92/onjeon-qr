import { BrowserQRCodeReader } from '@zxing/browser';
import { BarcodeFormat, ChecksumException, FormatException, NotFoundException, Result } from '@zxing/library';
import jsQR from 'jsqr';

export class QrReader extends BrowserQRCodeReader {
  override decodeFromCanvas(canvas: HTMLCanvasElement): Result {
    try {
      return super.decodeFromCanvas(canvas);
    } catch (cause) {
      if (!(cause instanceof NotFoundException || cause instanceof ChecksumException || cause instanceof FormatException)) throw cause;
      // Dense signed QRs can confuse ZXing's finder selection when rotated.
      // The fallback only decodes pixels; the resulting text still needs server verification.
      let source = canvas;
      const maxDimension = Math.max(canvas.width, canvas.height);
      if (maxDimension > 1280) {
        source = document.createElement('canvas');
        source.width = Math.round(canvas.width * 1280 / maxDimension);
        source.height = Math.round(canvas.height * 1280 / maxDimension);
        source.getContext('2d')?.drawImage(canvas, 0, 0, source.width, source.height);
      }
      const context = source.getContext('2d', { willReadFrequently: true });
      if (!context) throw cause;
      const pixels = context.getImageData(0, 0, source.width, source.height);
      const decoded = jsQR(pixels.data, source.width, source.height, { inversionAttempts: 'dontInvert' });
      if (!decoded) throw cause;
      return new Result(decoded.data, new Uint8Array(decoded.binaryData), decoded.binaryData.length * 8, [], BarcodeFormat.QR_CODE, Date.now());
    }
  }
}
