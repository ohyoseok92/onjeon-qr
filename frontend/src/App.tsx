import type { IScannerControls } from '@zxing/browser';
import { useEffect, useRef, useState, type FormEvent } from 'react';

type VerifyResult = {
  status: 'trusted' | 'blocked' | 'warning';
  reason: string;
  institution_name?: string;
  destination?: string;
  purpose?: string;
  expires_at?: number;
  qr_id?: string;
  host?: string;
  redirects?: number;
  signals?: string[];
};

type IssueResult = {
  qr_id: string;
  qr_text: string;
  qr_png_base64: string;
  expires_at: number;
  institution_id: string;
};

const API_BASE = import.meta.env.DEV ? '/api' : '';

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
  unsigned_qr: '기관 서명 없음',
  install_file: '앱 설치 파일로 보이는 주소',
  idn_domain: '국제화 도메인',
  lookalike_domain: '등록된 기관 주소와 비슷한 도메인',
  official_domain_unverified: '기관 도메인과 일치하지만 발급 여부는 확인 불가',
  left_official_domain: '기관 도메인 밖으로 이동',
  head_not_supported: '서버가 사전 확인 요청을 지원하지 않음',
  network_unavailable: '네트워크 확인 실패',
  redirect_limit: '이동 횟수 초과',
  tls_invalid: '인증서 검증 실패',
  analyzer_busy: '분석기 사용량 초과',
  analysis_timeout: '분석 시간 초과',
};

function trustedHref(destination?: string): string | undefined {
  if (!destination) return undefined;
  try {
    const url = new URL(destination);
    if (url.protocol === 'https:' && !url.username && !url.password) return url.href;
  } catch {
    return undefined;
  }
  return undefined;
}

function CitizenView() {
  const [qrText, setQrText] = useState('');
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const videoRef = useRef<HTMLVideoElement>(null);
  const controlsRef = useRef<IScannerControls | null>(null);
  const scanHandledRef = useRef(false);

  function stopCamera() {
    controlsRef.current?.stop();
    controlsRef.current = null;
    const stream = videoRef.current?.srcObject;
    if (stream instanceof MediaStream) stream.getTracks().forEach((track) => track.stop());
    if (videoRef.current) videoRef.current.srcObject = null;
    setScanning(false);
  }

  useEffect(() => () => {
    controlsRef.current?.stop();
    const stream = videoRef.current?.srcObject;
    if (stream instanceof MediaStream) stream.getTracks().forEach((track) => track.stop());
  }, []);

  async function verify(value: string) {
    setResult(null);
    setError('');
    const text = value.trim();
    setBusy(true);
    try {
      const signed = text.startsWith('onqr:v1:');
      const response = await fetch(`${API_BASE}/${signed ? 'verify' : 'analyze'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ qr_text: text }),
        cache: 'no-store',
      });
      if (response.status === 429) throw new Error('요청이 많습니다. 잠시 뒤 다시 시도해 주세요.');
      if (response.status === 413 || response.status === 422) throw new Error('QR 원문이 너무 길거나 형식이 올바르지 않습니다.');
      if (!response.ok) throw new Error('검증 서버에 연결할 수 없습니다. 잠시 뒤 다시 시도해 주세요.');
      setResult((await response.json()) as VerifyResult);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '검증을 마치지 못했습니다.');
    } finally {
      setBusy(false);
    }
  }

  async function startCamera() {
    setError('');
    setResult(null);
    scanHandledRef.current = false;
    if (!navigator.mediaDevices?.getUserMedia) {
      setError('이 환경에서는 카메라를 사용할 수 없습니다. QR 원문을 붙여 넣어 주세요.');
      return;
    }
    if (!videoRef.current) return;
    setScanning(true);
    try {
      const { BrowserQRCodeReader } = await import('@zxing/browser');
      const reader = new BrowserQRCodeReader();
      const controls = await reader.decodeFromConstraints(
        { audio: false, video: { facingMode: 'environment' } },
        videoRef.current,
        (decoded, _error, activeControls) => {
          if (!decoded || scanHandledRef.current) return;
          scanHandledRef.current = true;
          const text = decoded.getText();
          activeControls.stop();
          controlsRef.current = null;
          setScanning(false);
          setQrText(text);
          void verify(text);
        },
      );
      if (scanHandledRef.current) controls.stop();
      else controlsRef.current = controls;
    } catch {
      stopCamera();
      setError('카메라를 열지 못했습니다. 브라우저 권한을 확인하거나 QR 원문을 붙여 넣어 주세요.');
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    stopCamera();
    void verify(qrText);
  }

  const destination = result?.status === 'trusted' ? trustedHref(result.destination) : undefined;

  return (
    <section className="content-grid">
      <div className="main-panel">
        <p className="eyebrow">시민용 검증</p>
        <h1>열기 전에 확인하세요.</h1>
        <p className="lead">온전 QR을 스캔하면 발급기관과 유효 상태를 확인합니다. 검증이 끝나기 전에는 링크를 열지 않습니다.</p>

        <div className="scanner-card">
          <div className="scanner-preview">
            <video ref={videoRef} playsInline muted aria-label="QR 카메라 화면" className={scanning ? 'visible' : ''} />
            {!scanning && <div className="scanner-placeholder"><span className="scan-icon">▣</span><span>카메라를 켜서 QR을 읽어 주세요</span></div>}
          </div>
          <div className="scanner-actions">
            {scanning ? <button type="button" onClick={stopCamera} className="secondary">카메라 끄기</button> : <button type="button" onClick={() => void startCamera()}>카메라로 스캔</button>}
            <span>카메라 권한은 스캔할 때만 사용합니다.</span>
          </div>
        </div>

        <form onSubmit={submit} className="paste-form">
          <label htmlFor="qr-text">QR 원문으로 확인</label>
          <textarea id="qr-text" value={qrText} onChange={(event) => setQrText(event.target.value)} placeholder="onqr:v1:..." rows={3} maxLength={4096} />
          <button type="submit" className="secondary" disabled={!qrText.trim() || busy}>{busy ? '확인 중…' : '원문 검증'}</button>
        </form>
      </div>

      <aside className="result-panel" aria-live="polite">
        <p className="eyebrow">검증 결과</p>
        {busy && <div className="empty-result"><span className="result-mark">⋯</span><h2>서명을 확인하고 있습니다</h2><p>결과가 나오기 전에는 링크를 열지 마세요.</p></div>}
        {!busy && error && <div className="result-state blocked"><span className="result-mark">!</span><h2>확인하지 못했습니다</h2><p>{error}</p><p>연결 문제 동안에는 기관 확인 결과를 제공할 수 없습니다.</p></div>}
        {!busy && !error && !result && <div className="empty-result"><span className="result-mark">✓</span><h2>아직 검증 전입니다</h2><p>QR을 스캔하거나 원문을 붙여 넣으면 결과가 이곳에 나타납니다.</p></div>}
        {!busy && result?.status === 'trusted' && (
          <div className="result-state trusted">
            <span className="result-mark">✓</span>
            <p className="status-label">서명과 발급 상태 확인</p>
            <h2>{result.institution_name}</h2>
            <dl><dt>발급 목적</dt><dd>{result.purpose}</dd><dt>목적지</dt><dd className="breakable">{result.destination}</dd><dt>유효기간</dt><dd>{result.expires_at ? new Date(result.expires_at * 1000).toLocaleString('ko-KR') : '확인 불가'}</dd></dl>
            <p className="fine-print">서명은 표시된 목적지의 발급 상태를 증명합니다. 이동 후의 화면과 리다이렉트는 별도로 확인하세요.</p>
            {destination && <a href={destination} target="_blank" rel="noopener noreferrer" className="link-button">목적지 열기 ↗</a>}
          </div>
        )}
        {!busy && result?.status === 'blocked' && <div className="result-state blocked"><span className="result-mark">×</span><p className="status-label">이동 차단</p><h2>신뢰할 수 없는 QR입니다</h2><p>{reasons[result.reason] ?? '검증 조건을 통과하지 못했습니다.'}</p><p className="fine-print">안내문에 적힌 기관의 공식 연락처로 확인해 주세요.</p></div>}
        {!busy && result?.status === 'warning' && <div className="result-state warning"><span className="result-mark">?</span><p className="status-label">미서명 QR 분석</p><h2>발급기관을 확인할 수 없습니다</h2><p>{reasons[result.reason] ?? '주소를 살펴봤지만 안전을 보증할 수 없습니다.'}</p>{result.host && <p>확인한 도메인: {result.host}</p>}{result.signals && <ul>{result.signals.map((signal) => <li key={signal}>{signalLabels[signal] ?? signal}</li>)}</ul>}<p className="fine-print">이 분석은 기관 인증이 아닙니다. 링크는 제공하지 않습니다.</p></div>}
      </aside>
    </section>
  );
}

function IssuerView() {
  const [institutionId, setInstitutionId] = useState('');
  const [token, setToken] = useState('');
  const [destination, setDestination] = useState('');
  const [purpose, setPurpose] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [issued, setIssued] = useState<IssueResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [revoked, setRevoked] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setIssued(null);
    setRevoked(false);
    try {
      const response = await fetch(`${API_BASE}/institutions/${encodeURIComponent(institutionId)}/qrs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ destination, purpose, expires_at: new Date(expiresAt).toISOString(), include_png: true }),
        cache: 'no-store',
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(typeof body.detail === 'string' ? body.detail : '발급 요청을 처리하지 못했습니다.');
      }
      setIssued({ ...(await response.json()) as IssueResult, institution_id: institutionId });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '발급 요청을 처리하지 못했습니다.');
    } finally {
      setBusy(false);
    }
  }

  async function revoke() {
    if (!issued) return;
    setBusy(true);
    setError('');
    try {
      const response = await fetch(`${API_BASE}/institutions/${encodeURIComponent(issued.institution_id)}/qrs/${encodeURIComponent(issued.qr_id)}/revoke`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        cache: 'no-store',
      });
      if (!response.ok) throw new Error('폐기 요청을 처리하지 못했습니다.');
      setRevoked(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '폐기 요청을 처리하지 못했습니다.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="issuer-layout">
      <div className="main-panel">
        <p className="eyebrow">기관용 발급</p>
        <h1>공식 안내 QR 발급</h1>
        <p className="lead">등록된 기관과 공식 도메인만 발급할 수 있습니다. 발급 토큰은 브라우저에 저장하지 않습니다.</p>
        <form onSubmit={(event) => void submit(event)} className="issuer-form">
          <label htmlFor="institution">기관 ID</label><input id="institution" value={institutionId} onChange={(event) => setInstitutionId(event.target.value)} required pattern="[a-z0-9][a-z0-9-]{1,39}" placeholder="demo-city" />
          <label htmlFor="token">기관 발급 토큰</label><input id="token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} required />
          <label htmlFor="destination">공식 목적지</label><input id="destination" type="url" value={destination} onChange={(event) => setDestination(event.target.value)} required placeholder="https://city.example.org/notice" />
          <label htmlFor="purpose">발급 목적</label><input id="purpose" value={purpose} onChange={(event) => setPurpose(event.target.value)} required maxLength={160} placeholder="주차요금 안내" />
          <label htmlFor="expires">유효기간</label><input id="expires" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} required />
          <button type="submit" disabled={busy}>{busy ? '처리 중…' : '서명 QR 발급'}</button>
        </form>
      </div>
      <aside className="result-panel" aria-live="polite">
        <p className="eyebrow">발급 결과</p>
        {error && <p className="form-error" role="alert">{error}</p>}
        {!issued && <div className="empty-result"><span className="result-mark">▣</span><h2>발급 대기 중</h2><p>기관 정보와 공식 목적지를 입력해 주세요.</p></div>}
        {issued && <div className="issued-result">
          <h2>{revoked ? '폐기된 QR' : '서명 QR 발급 완료'}</h2>
          <img src={`data:image/png;base64,${issued.qr_png_base64}`} alt="발급된 온전 QR" />
          <p className="fine-print">QR ID: {issued.qr_id}</p>
          <a className="link-button" href={`data:image/png;base64,${issued.qr_png_base64}`} download={`onjeon-${issued.qr_id}.png`}>PNG 내려받기</a>
          {!revoked && <button type="button" className="danger" onClick={() => void revoke()} disabled={busy}>이 QR 폐기</button>}
        </div>}
      </aside>
    </section>
  );
}

export default function App() {
  const [view, setView] = useState<'citizen' | 'issuer'>('citizen');
  return (
    <div className="app-shell">
      <header className="site-header">
        <div className="brand"><span className="brand-icon">▣</span><div><strong>온전 QR</strong><small>공공 안내문 QR 신뢰 확인</small></div></div>
        <nav aria-label="주요 메뉴"><button type="button" className={view === 'citizen' ? 'active' : ''} onClick={() => setView('citizen')}>시민 검증</button><button type="button" className={view === 'issuer' ? 'active' : ''} onClick={() => setView('issuer')}>기관 발급</button></nav>
      </header>
      <main>{view === 'citizen' ? <CitizenView /> : <IssuerView />}</main>
      <footer><span>온전 QR 시제품</span><span>검증 전에는 어떤 링크도 자동으로 열지 않습니다.</span></footer>
    </div>
  );
}
