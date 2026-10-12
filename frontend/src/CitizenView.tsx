import type { IScannerControls } from '@zxing/browser';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { API_BASE, formatTime, trustedHref, type VerifyResult } from './api';

const reasons: Record<string, string> = {
  invalid_format: '온전 QR 서명 형식이 아닙니다.',
  unknown_issuer: '등록되지 않은 발급기관입니다.',
  invalid_signature: '서명이 일치하지 않습니다. QR 내용이 바뀌었을 수 있습니다.',
  destination_policy: '기관이 등록한 공식 도메인과 목적지가 일치하지 않습니다.',
  unknown_qr: '발급 기록을 확인할 수 없습니다.',
  revoked: '기관이 이 QR을 폐기했습니다.',
  issuer_disabled: '발급기관이 비활성화됐습니다.',
  key_revoked: '서명키가 폐기됐습니다.',
  expired_or_invalid_time: '유효기간이 지났거나 발급 시간이 올바르지 않습니다.',
  unsupported_url: '분석할 수 없는 QR 주소입니다.',
  insecure_scheme: '암호화되지 않은 HTTP 주소입니다.',
  non_public_address: '내부망 또는 비공개 주소로 연결될 수 있습니다.',
  unsafe_redirect: '이동 과정에서 안전하지 않은 주소가 발견됐습니다.',
  redirect_loop: '주소가 반복해서 이동합니다.',
  network_unavailable: '네트워크 분석을 완료하지 못했습니다.',
  redirect_unknown: '이동할 주소를 확인할 수 없습니다.',
  redirect_limit: '주소 이동이 허용 횟수를 넘었습니다.',
  tls_invalid: '연결한 서버의 인증서를 확인할 수 없습니다.',
  analyzer_busy: '주소 분석 요청이 많습니다. 잠시 뒤 다시 시도해 주세요.',
  analysis_timeout: '주소 분석 제한시간을 넘었습니다. 결과를 확인할 수 없습니다.',
};
const signalLabels: Record<string, string> = {
  unsigned_qr: '기관 서명 없음', install_file: '앱 설치 파일로 보이는 주소',
  idn_domain: '국제화 도메인', lookalike_domain: '등록된 기관 주소와 비슷한 도메인',
  official_domain_unverified: '기관 도메인과 일치하지만 발급 여부는 확인 불가',
  left_official_domain: '기관 도메인 밖으로 이동', head_not_supported: '서버가 사전 확인 요청을 지원하지 않음',
  network_unavailable: '네트워크 확인 실패', redirect_limit: '이동 횟수 초과',
  tls_invalid: '인증서 검증 실패', analyzer_busy: '분석 요청이 많음', analysis_timeout: '분석 시간 초과',
};

export default function CitizenView({ initialText = '' }: { initialText?: string }) {
  const [qrText, setQrText] = useState(initialText);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [cameraStarting, setCameraStarting] = useState(false);
  const [error, setError] = useState('');
  const videoRef = useRef<HTMLVideoElement>(null);
  const resultRef = useRef<HTMLElement>(null);
  const controlsRef = useRef<IScannerControls | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const mountedRef = useRef(false);
  const scanGenerationRef = useRef(0);
  const cameraPendingRef = useRef(false);
  const requestRef = useRef<AbortController | null>(null);

  function releaseVideo(video: HTMLVideoElement | null) {
    const stream = video?.srcObject;
    if (stream instanceof MediaStream) stream.getTracks().forEach((track) => track.stop());
    if (video) video.srcObject = null;
  }
  function stopCamera() {
    scanGenerationRef.current += 1;
    controlsRef.current?.stop();
    controlsRef.current = null;
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null;
    releaseVideo(videoRef.current);
    if (mountedRef.current) setScanning(false);
  }
  function clearVerification() {
    requestRef.current?.abort();
    requestRef.current = null;
    setBusy(false);
    setResult(null);
    setError('');
  }
  useEffect(() => {
    mountedRef.current = true;
    const video = videoRef.current;
    const onVisibility = () => { if (document.hidden) stopCamera(); };
    const onPageHide = () => stopCamera();
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('pagehide', onPageHide);
    return () => {
      mountedRef.current = false;
      scanGenerationRef.current += 1;
      requestRef.current?.abort();
      controlsRef.current?.stop();
      streamRef.current?.getTracks().forEach((track) => track.stop());
      releaseVideo(video);
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('pagehide', onPageHide);
    };
  }, []);

  async function verify(value: string) {
    if (requestRef.current) return;
    const text = value.trim();
    if (!text) return;
    const request = new AbortController();
    requestRef.current = request;
    setResult(null);
    setError('');
    setBusy(true);
    const timeout = window.setTimeout(() => request.abort(), 25000);
    try {
      const signed = text.startsWith('onqr:');
      const response = await fetch(`${API_BASE}/${signed ? 'verify' : 'analyze'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qr_text: text }), cache: 'no-store', signal: request.signal,
      });
      if (response.status === 429) throw new Error('요청이 많습니다. 잠시 뒤 다시 시도해 주세요.');
      if (response.status === 413 || response.status === 422) throw new Error('QR 원문이 너무 길거나 형식이 올바르지 않습니다.');
      if (!response.ok) throw new Error('검증 서버에 연결할 수 없습니다. 잠시 뒤 다시 시도해 주세요.');
      const data = await response.json() as VerifyResult;
      if (!['trusted', 'blocked', 'warning'].includes(data.status)) throw new Error('서버 결과를 확인하지 못했습니다. 다시 시도해 주세요.');
      if (mountedRef.current && requestRef.current === request) setResult(data);
    } catch (cause) {
      if (mountedRef.current && requestRef.current === request) setError(request.signal.aborted ? '확인 시간이 초과됐습니다. 연결 상태를 확인하고 다시 시도해 주세요.' : cause instanceof Error && !(cause instanceof TypeError) ? cause.message : '서버에 연결하지 못했습니다. 네트워크 연결을 확인해 주세요.');
    } finally {
      window.clearTimeout(timeout);
      if (mountedRef.current && requestRef.current === request) {
        requestRef.current = null;
        setBusy(false);
        resultRef.current?.focus({ preventScroll: true });
      }
    }
  }

  async function startCamera() {
    if (cameraPendingRef.current || requestRef.current) return;
    clearVerification();
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('이 환경에서는 카메라를 사용할 수 없습니다. QR 원문을 붙여 넣어 주세요.');
      return;
    }
    const video = videoRef.current;
    if (!video) return;
    const generation = ++scanGenerationRef.current;
    cameraPendingRef.current = true;
    setCameraStarting(true);
    setScanning(true);
    let handled = false;
    let stream: MediaStream | null = null;
    try {
      const { QrReader } = await import('./QrReader');
      if (!mountedRef.current || generation !== scanGenerationRef.current) return;
      const reader = new QrReader();
      stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: { ideal: 'environment' } } });
      if (!mountedRef.current || generation !== scanGenerationRef.current) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      streamRef.current = stream;
      const controls = await reader.decodeFromStream(
        stream, video,
        (decoded, _error, activeControls) => {
          if (!mountedRef.current || generation !== scanGenerationRef.current) {
            activeControls.stop();
            releaseVideo(video);
            return;
          }
          if (!decoded || handled) return;
          handled = true;
          activeControls.stop();
          stopCamera();
          const text = decoded.getText();
          setQrText(text);
          void verify(text);
        },
      );
      if (handled || !mountedRef.current || generation !== scanGenerationRef.current) {
        controls.stop();
        releaseVideo(video);
      } else controlsRef.current = controls;
    } catch (cause) {
      stream?.getTracks().forEach((track) => track.stop());
      if (mountedRef.current && generation === scanGenerationRef.current) {
        stopCamera();
        setError(cause instanceof DOMException && cause.name === 'NotAllowedError' ? '카메라 권한이 필요합니다. 브라우저 권한을 확인하거나 원문을 붙여 넣어 주세요.' : '카메라를 열지 못했습니다. 다른 앱의 카메라 사용 여부를 확인하거나 원문을 붙여 넣어 주세요.');
      }
    } finally {
      cameraPendingRef.current = false;
      if (mountedRef.current) setCameraStarting(false);
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    stopCamera();
    void verify(qrText);
  }
  const destination = result?.status === 'trusted' ? trustedHref(result.destination) : undefined;

  return <section className="content-grid">
    <div className="main-panel">
      <p className="eyebrow">시민 검증</p><h1>QR을 열기 전에<br />한 번 더 확인하세요.</h1>
      <p className="lead">공공 안내문의 QR을 스캔해 발급기관과 유효기간을 확인하세요. 확인이 끝나면 공식 목적지를 직접 열 수 있습니다.</p>
      <div className="scanner-card">
        <div className="scanner-preview"><video ref={videoRef} playsInline muted aria-label="QR 카메라 화면" className={scanning ? 'visible' : ''} />{!scanning && <div className="scanner-placeholder"><span className="scan-icon" aria-hidden="true">▣</span><span>사각형 안에 QR을 맞춰 주세요</span></div>}{scanning && <span className="camera-caption">{cameraStarting ? '카메라를 준비하고 있습니다…' : 'QR을 인식하면 자동으로 확인합니다'}</span>}</div>
        <div className="scanner-actions">{scanning ? <button type="button" onClick={stopCamera} className="secondary">카메라 끄기</button> : <button type="button" disabled={busy || cameraStarting} onClick={() => void startCamera()}>{cameraStarting ? '카메라 종료 중…' : '카메라로 스캔'}</button>}<span>스캔을 마치면 카메라가 꺼집니다.</span></div>
      </div>
      <form onSubmit={submit} className="paste-form"><label htmlFor="qr-text">QR 원문 또는 주소로 확인</label><textarea id="qr-text" value={qrText} onChange={(event) => { setQrText(event.target.value); stopCamera(); clearVerification(); }} placeholder="onqr:v1:… 또는 https://…" rows={3} maxLength={4096} autoCapitalize="off" autoCorrect="off" spellCheck={false} aria-describedby="qr-help" /><p id="qr-help" className="field-help">서명 없는 주소는 위험 징후만 확인하며, 이동 링크를 제공하지 않습니다.</p><button type="submit" className="secondary" disabled={!qrText.trim() || busy}>{busy ? '확인 중…' : 'QR 확인'}</button></form>
    </div>
    <aside ref={resultRef} tabIndex={-1} className="result-panel" aria-live="polite" aria-atomic="true" aria-busy={busy} aria-label="QR 검증 결과">
      <p className="eyebrow">검증 결과</p>
      {busy && <div className="empty-result"><span className="result-mark loading" aria-hidden="true">⋯</span><h2>QR을 확인하고 있습니다</h2><p>발급 상태와 주소를 확인하는 동안 잠시 기다려 주세요.</p></div>}
      {!busy && error && <div className="result-state blocked"><span className="result-mark" aria-hidden="true">!</span><h2>확인하지 못했습니다</h2><p>{error}</p></div>}
      {!busy && !error && !result && <div className="empty-result"><span className="result-mark" aria-hidden="true">✓</span><h2>아직 검증 전입니다</h2><p>QR을 스캔하거나 원문을 붙여 넣으면<br />이곳에서 결과를 확인할 수 있습니다.</p></div>}
      {!busy && result?.status === 'trusted' && <div className="result-state trusted"><span className="result-mark" aria-hidden="true">✓</span><p className="status-label">기관 발급 확인 완료</p><h2>{result.institution_name}</h2><dl><dt>발급 목적</dt><dd>{result.purpose}</dd><dt>목적지</dt><dd className="breakable">{result.destination}</dd><dt>유효기간</dt><dd>{formatTime(result.expires_at)}</dd></dl><p className="fine-print">확인한 목적지를 기관이 발급했습니다. 이동 후 주소가 달라지면 공식 도메인인지 다시 확인해 주세요.</p>{destination ? <a href={destination} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" className="link-button">공식 목적지 열기 ↗</a> : <p className="form-error">목적지 주소를 안전하게 열 수 없습니다.</p>}</div>}
      {!busy && result?.status === 'blocked' && <div className="result-state blocked"><span className="result-mark" aria-hidden="true">×</span><p className="status-label">이동 차단</p><h2>사용할 수 없는 QR입니다</h2><p>{reasons[result.reason] ?? '검증 조건을 통과하지 못했습니다.'}</p><p className="fine-print">기관의 공식 홈페이지나 연락처로 안내 내용을 확인해 주세요.</p></div>}
      {!busy && result?.status === 'warning' && <div className="result-state warning"><span className="result-mark" aria-hidden="true">?</span><p className="status-label">주의가 필요한 QR</p><h2>발급기관을 확인할 수 없습니다</h2><p>{reasons[result.reason] ?? '주소를 살펴봤지만 안전을 보증할 수 없습니다.'}</p>{result.host && <p className="breakable">확인한 도메인: {result.host}</p>}{result.signals && <ul className="signal-list">{[...new Set(result.signals)].map((signal) => <li key={signal}>{signalLabels[signal] ?? '추가 확인이 필요한 주소'}</li>)}</ul>}<p className="fine-print">기관의 공식 홈페이지에서 안내 내용을 찾아보세요.</p></div>}
    </aside>
  </section>;
}
