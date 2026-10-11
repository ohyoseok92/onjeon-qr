import { useEffect, useRef, useState, type FormEvent } from 'react';
import { API_BASE, checkResponse, formatTime, trustedHref } from './api';

type Session = { id: string; token: string };
type IssueResult = { qr_id: string; qr_text: string; qr_png_base64: string; expires_at: number };
type QrRecord = { qr_id: string; purpose: string | null; issued_at: number | null; expires_at: number | null; key_version: string | null; revoked_at: number | null; status: 'active' | 'revoked' | 'expired' | 'legacy' };
type Dashboard = {
  institution: { id: string; name: string; official_domains: string[]; active_key_version: string | null };
  qrs: QrRecord[];
  audit: { id: number; qr_id: string | null; action: string; occurred_at: number }[];
  counts: { active: number; revoked: number; expired: number; total: number };
};
const statusNames: Record<QrRecord['status'], string> = { active: '유효', revoked: '폐기', expired: '만료', legacy: '이전 발급' };
const auditNames: Record<string, string> = {
  issued: 'QR 발급', revoked: 'QR 폐기', registered: '기관 등록',
  key_rotated: '발급키 변경', key_activated: '발급키 활성화', key_revoked: '발급키 폐기',
  token_rotated: '발급 토큰 변경', institution_disabled: '기관 비활성화', institution_enabled: '기관 활성화',
};
function localDate(value: Date) {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
function readableError(cause: unknown, fallback: string) {
  if (cause instanceof DOMException && cause.name === 'AbortError') return '응답 시간이 초과됐습니다. 새로고침해 처리 결과를 확인해 주세요.';
  return cause instanceof Error && !(cause instanceof TypeError) ? cause.message : fallback;
}

export default function IssuerView({ onVerify }: { onVerify: (text: string) => void }) {
  const [institutionId, setInstitutionId] = useState('');
  const [token, setToken] = useState('');
  const [session, setSession] = useState<Session | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [destination, setDestination] = useState('');
  const [purpose, setPurpose] = useState('');
  const [expiresAt, setExpiresAt] = useState(() => localDate(new Date(Date.now() + 7 * 86400000)));
  const [issued, setIssued] = useState<IssueResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [filter, setFilter] = useState('all');
  const mountedRef = useRef(false);
  const generationRef = useRef(0);
  const requestRef = useRef<AbortController | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; generationRef.current += 1; requestRef.current?.abort(); };
  }, []);
  function disconnect() {
    generationRef.current += 1;
    requestRef.current?.abort();
    requestRef.current = null;
    setSession(null); setDashboard(null); setToken(''); setIssued(null);
    setDestination(''); setPurpose(''); setConfirmId(null); setBusy(false); setError(''); setNotice('');
  }
  useEffect(() => {
    if (!session) return;
    const idleLimit = 5 * 60 * 1000;
    let lastActivity = Date.now();
    let timer: number;
    function checkIdle(): boolean {
      const elapsed = Date.now() - lastActivity;
      if (elapsed >= idleLimit || elapsed < 0) {
        disconnect();
        setNotice('5분 동안 사용하지 않아 연결을 해제했습니다. 다시 연결해 주세요.');
        return false;
      }
      window.clearTimeout(timer);
      timer = window.setTimeout(checkIdle, idleLimit - elapsed);
      return true;
    }
    function activity() {
      // A delayed background timer must not let the first resumed input renew an expired session.
      if (!checkIdle()) return;
      lastActivity = Date.now();
      window.clearTimeout(timer);
      timer = window.setTimeout(checkIdle, idleLimit);
    }
    function resume() { checkIdle(); }
    timer = window.setTimeout(checkIdle, idleLimit);
    for (const event of ['pointerdown', 'keydown', 'input']) document.addEventListener(event, activity);
    document.addEventListener('visibilitychange', resume);
    window.addEventListener('focus', resume);
    return () => {
      window.clearTimeout(timer);
      for (const event of ['pointerdown', 'keydown', 'input']) document.removeEventListener(event, activity);
      document.removeEventListener('visibilitychange', resume);
      window.removeEventListener('focus', resume);
    };
  }, [session]);
  async function requestDashboard(current: Session, controller: AbortController): Promise<Dashboard> {
    const response = await fetch(`${API_BASE}/institutions/${encodeURIComponent(current.id)}/dashboard`, {
      headers: { Authorization: `Bearer ${current.token}` }, cache: 'no-store', signal: controller.signal,
    });
    await checkResponse(response, '기관 조회');
    return await response.json() as Dashboard;
  }
  // Block double clicks before React commits the disabled state.
  async function operate(task: (controller: AbortController, isCurrent: () => boolean) => Promise<void>) {
    if (requestRef.current) return;
    const generation = generationRef.current;
    const controller = new AbortController();
    requestRef.current = controller;
    setBusy(true); setError(''); setNotice('');
    const isCurrent = () => mountedRef.current && generation === generationRef.current;
    const timeout = window.setTimeout(() => controller.abort(), 25000);
    try { await task(controller, isCurrent); }
    catch (cause) { if (isCurrent()) setError(readableError(cause, '서버에 연결하지 못했습니다. 연결 상태를 확인해 주세요.')); }
    finally {
      window.clearTimeout(timeout);
      if (isCurrent()) { requestRef.current = null; setBusy(false); }
    }
  }
  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const current = { id: institutionId.trim(), token: token.trim() };
    if (!current.id || !current.token) return;
    void operate(async (controller, isCurrent) => {
      const data = await requestDashboard(current, controller);
      if (isCurrent()) { setSession(current); setDashboard(data); setToken(''); setNotice('기관에 연결했습니다.'); }
    });
  }
  function refresh() {
    if (!session) return;
    const current = session;
    void operate(async (controller, isCurrent) => {
      const data = await requestDashboard(current, controller);
      if (isCurrent()) { setDashboard(data); setNotice('최신 발급 상태를 불러왔습니다.'); }
    });
  }
  async function refreshAfterChange(current: Session, controller: AbortController, isCurrent: () => boolean, message: string) {
    try {
      const data = await requestDashboard(current, controller);
      if (isCurrent()) { setDashboard(data); setNotice(message); }
    } catch (cause) {
      if (isCurrent()) setError(`${message} 목록을 갱신하지 못했습니다. 새로고침해 주세요. ${readableError(cause, '')}`);
    }
  }
  function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session || !dashboard) return;
    const href = trustedHref(destination.trim());
    const expiry = new Date(expiresAt).getTime();
    if (!href || !dashboard.institution.official_domains.includes(new URL(href).hostname)) {
      setError('등록된 공식 도메인의 HTTPS 주소를 입력해 주세요.'); return;
    }
    if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + 30 * 86400000) {
      setError('유효기간은 현재부터 30일 이내로 설정해 주세요.'); return;
    }
    if (purpose.trim().length < 2) { setError('발급 목적을 2자 이상 입력해 주세요.'); return; }
    const current = session;
    void operate(async (controller, isCurrent) => {
      const response = await fetch(`${API_BASE}/institutions/${encodeURIComponent(current.id)}/qrs`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${current.token}` },
        body: JSON.stringify({ destination: href, purpose: purpose.trim(), expires_at: new Date(expiry).toISOString(), include_png: true }),
        cache: 'no-store', signal: controller.signal,
      });
      await checkResponse(response, 'QR 발급');
      const data = await response.json() as IssueResult;
      if (isCurrent()) { setIssued(data); setConfirmId(null); }
      await refreshAfterChange(current, controller, isCurrent, '서명 QR을 발급했습니다.');
    });
  }
  function revoke(qrId: string) {
    if (!session) return;
    const current = session;
    void operate(async (controller, isCurrent) => {
      const response = await fetch(`${API_BASE}/institutions/${encodeURIComponent(current.id)}/qrs/${encodeURIComponent(qrId)}/revoke`, {
        method: 'POST', headers: { Authorization: `Bearer ${current.token}` }, cache: 'no-store', signal: controller.signal,
      });
      await checkResponse(response, 'QR 폐기');
      if (isCurrent()) {
        setConfirmId(null);
        setDashboard((previous) => previous ? { ...previous, qrs: previous.qrs.map((qr) => qr.qr_id === qrId ? { ...qr, status: 'revoked', revoked_at: Math.floor(Date.now() / 1000) } : qr) } : previous);
      }
      await refreshAfterChange(current, controller, isCurrent, 'QR을 폐기했습니다. 이후 검증부터 차단됩니다.');
    });
  }
  async function copyQr() {
    if (!issued) return;
    const generation = generationRef.current;
    try {
      await navigator.clipboard.writeText(issued.qr_text);
      if (mountedRef.current && generation === generationRef.current) setNotice('QR 원문을 복사했습니다.');
    } catch {
      if (mountedRef.current && generation === generationRef.current) setError('복사 권한을 사용할 수 없습니다. QR 원문을 선택해 직접 복사해 주세요.');
    }
  }
  const issuedRevoked = !!issued && dashboard?.qrs.some((qr) => qr.qr_id === issued.qr_id && qr.status === 'revoked');
  const rows = dashboard?.qrs.filter((qr) => filter === 'all' || qr.status === filter) ?? [];
  const messages = <div className="messages" aria-live="polite" aria-atomic="true">{error && <p className="form-error" role="alert">{error}</p>}{notice && <p className="form-notice">{notice}</p>}</div>;

  if (!session || !dashboard) return <section className="issuer-login">
    <div className="main-panel"><p className="eyebrow">기관 관리</p><h1>공식 안내를<br />안심하고 전하세요.</h1><p className="lead">기관 계정으로 연결해 안내 QR을 발급하고, 사용을 마친 QR은 폐기하세요. 발급과 폐기 기록도 함께 확인할 수 있습니다.</p><div className="intro-features"><span>공식 도메인 발급</span><span>QR 사용 중지</span><span>변경 기록 확인</span></div></div>
    <div className="panel login-panel"><h2>기관 계정 연결</h2><p className="field-help">관리자에게 받은 기관 ID와 발급 토큰을 입력해 주세요.</p>{messages}<form onSubmit={connect} className="stack-form"><label htmlFor="institution">기관 ID</label><input id="institution" value={institutionId} onChange={(event) => setInstitutionId(event.target.value)} required pattern="[a-z0-9][a-z0-9-]{1,39}" maxLength={40} placeholder="demo-city" autoCapitalize="off" autoCorrect="off" spellCheck={false} disabled={busy} /><label htmlFor="token">기관 발급 토큰</label><input id="token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} required maxLength={512} disabled={busy} /><button type="submit" disabled={busy}>{busy ? '연결 중…' : '기관 연결'}</button></form><p className="fine-print">토큰은 이 화면을 사용하는 동안만 유지됩니다. 메뉴를 이동하거나 연결을 해제하면 다시 입력해야 합니다.</p></div>
  </section>;

  return <section className="dashboard-layout" aria-busy={busy}>
    <div className="dashboard-heading"><div><p className="eyebrow">기관 관리</p><h1>{dashboard.institution.name}</h1><p className="field-help breakable">등록 도메인 · {dashboard.institution.official_domains.join(', ')}</p></div><div className="button-row"><button type="button" className="secondary" onClick={refresh} disabled={busy}>새로고침</button><button type="button" className="quiet" onClick={disconnect}>연결 해제</button></div></div>
    {messages}
    <p className="fine-print">5분 동안 사용하지 않으면 연결이 해제됩니다.</p>
    <div className="stats-grid" aria-label="기관 QR 현황">{([['active', '유효 QR'], ['revoked', '폐기 QR'], ['expired', '만료 QR'], ['total', '전체 발급']] as const).map(([key, label]) => <div className={`stat-card ${key}`} key={key}><span>{label}</span><strong>{dashboard.counts[key].toLocaleString('ko-KR')}</strong></div>)}</div>
    <div className="issuer-layout">
      <div className="panel"><div className="section-heading"><h2>새 QR 발급</h2><span className="badge active">공식 안내</span></div><form onSubmit={issue} className="stack-form"><label htmlFor="destination">공식 목적지</label><input id="destination" type="url" value={destination} onChange={(event) => setDestination(event.target.value)} required maxLength={2048} placeholder={`https://${dashboard.institution.official_domains[0] ?? 'city.example.org'}/notice`} disabled={busy} aria-describedby="destination-help" /><p id="destination-help" className="field-help">위에 등록된 도메인의 HTTPS 주소를 사용할 수 있습니다.</p><label htmlFor="purpose">발급 목적</label><input id="purpose" value={purpose} onChange={(event) => setPurpose(event.target.value)} required minLength={2} maxLength={160} placeholder="주차요금 안내" disabled={busy} /><label htmlFor="expires">유효기간</label><input id="expires" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} required min={localDate(new Date())} max={localDate(new Date(Date.now() + 30 * 86400000))} disabled={busy} aria-describedby="expires-help" /><p id="expires-help" className="field-help">현재부터 30일 이내 · 이 기기의 현지 시간 기준</p>{!dashboard.institution.active_key_version && <p className="form-error">사용 가능한 발급키가 없습니다. 관리자에게 문의해 주세요.</p>}<button type="submit" disabled={busy || !dashboard.institution.active_key_version}>{busy ? '처리 중…' : '서명 QR 발급'}</button></form></div>
      <aside className="panel issue-panel" aria-label="발급 결과"><p className="eyebrow">발급 결과</p>{!issued ? <div className="empty-result"><span className="result-mark" aria-hidden="true">▣</span><h2>새 안내를 준비하세요</h2><p>발급한 QR을 내려받아<br />안내문에 사용할 수 있습니다.</p></div> : <div className="issued-result"><h2>{issuedRevoked ? '폐기된 QR' : '발급 완료'}</h2>{issuedRevoked && <p className="form-error">이 QR은 검증 시 차단됩니다. 안내문에서 제거해 주세요.</p>}<img src={`data:image/png;base64,${issued.qr_png_base64}`} alt={issuedRevoked ? '폐기된 온전 QR' : '발급된 온전 QR'} /><p className="fine-print">유효기간: {formatTime(issued.expires_at)}</p><p className="fine-print breakable">QR ID: {issued.qr_id}</p>{!issuedRevoked && <a className="link-button" href={`data:image/png;base64,${issued.qr_png_base64}`} download={`onjeon-${issued.qr_id}.png`}>QR 이미지 내려받기</a>}<div className="button-row"><button type="button" className="secondary" onClick={() => void copyQr()}>원문 복사</button><button type="button" className="secondary" onClick={() => onVerify(issued.qr_text)}>시민 화면에서 확인</button></div><details><summary>QR 원문 보기</summary><textarea aria-label="발급한 QR 원문" value={issued.qr_text} readOnly rows={3} spellCheck={false} onFocus={(event) => event.currentTarget.select()} /></details></div>}</aside>
    </div>
    <section className="panel records-panel"><div className="section-heading"><div><h2>발급 QR</h2><p className="field-help">최근 100건 · 폐기하면 즉시 사용이 중지됩니다.</p></div><div><label className="visually-hidden" htmlFor="status-filter">발급 상태 필터</label><select id="status-filter" value={filter} onChange={(event) => { setFilter(event.target.value); setConfirmId(null); }}><option value="all">모든 상태</option><option value="active">유효</option><option value="revoked">폐기</option><option value="expired">만료</option><option value="legacy">이전 발급</option></select></div></div>
      {rows.length === 0 ? <p className="empty-list">{dashboard.qrs.length ? '이 상태의 QR이 없습니다.' : '아직 발급한 QR이 없습니다. 위에서 첫 QR을 발급해 보세요.'}</p> : <ul className="qr-records">{rows.map((qr) => <li key={qr.qr_id}><div className="record-main"><div className="record-title"><strong>{qr.purpose || '이전 발급 QR'}</strong><span className={`badge ${qr.status}`}>{statusNames[qr.status]}</span></div><p className="fine-print breakable">{qr.qr_id}</p><p className="record-dates">발급 {formatTime(qr.issued_at)}<span aria-hidden="true"> · </span>만료 {formatTime(qr.expires_at)}</p></div>{qr.status !== 'revoked' && <div className="record-action">{confirmId === qr.qr_id ? <><p className="confirm-text">폐기 후에는 다시 사용할 수 없습니다.</p><div className="button-row"><button type="button" className="danger" onClick={() => revoke(qr.qr_id)} disabled={busy}>폐기 확정</button><button type="button" className="quiet" onClick={() => setConfirmId(null)} disabled={busy}>취소</button></div></> : <button type="button" className="danger" disabled={busy} onClick={() => setConfirmId(qr.qr_id)} aria-label={`${qr.purpose || '이전 발급 QR'} 폐기`}>폐기</button>}</div>}</li>)}</ul>}
    </section>
    <section className="panel records-panel"><div className="section-heading"><div><h2>변경 기록</h2><p className="field-help">최근 100건 · QR·기관 설정 변경 이력</p></div></div>{dashboard.audit.length === 0 ? <p className="empty-list">아직 변경 기록이 없습니다.</p> : <ol className="audit-list">{dashboard.audit.map((item) => <li key={item.id}><span className={`audit-dot ${item.action}`} aria-hidden="true" /><div><strong>{auditNames[item.action] ?? '기관 설정 변경'}</strong><p className="fine-print breakable">{item.qr_id || '기관 설정'}</p></div><time dateTime={new Date(item.occurred_at * 1000).toISOString()}>{formatTime(item.occurred_at)}</time></li>)}</ol>}</section>
  </section>;
}
