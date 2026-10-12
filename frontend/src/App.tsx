import { useState } from 'react';
import CitizenView from './CitizenView';
import IssuerView from './IssuerView';

export default function App() {
  const [view, setView] = useState<'citizen' | 'issuer'>('citizen');
  const [verificationText, setVerificationText] = useState('');
  function changeView(next: 'citizen' | 'issuer') {
    if (next === view) return;
    setVerificationText('');
    setView(next);
  }
  return <div className="app-shell">
    <a className="skip-link" href="#main-content">본문으로 이동</a>
    <header className="site-header"><div className="brand"><span className="brand-icon" aria-hidden="true">▣</span><div><strong>온전 QR</strong><small>공공 안내문 QR 신뢰 확인</small></div></div><nav aria-label="주요 메뉴"><button type="button" aria-current={view === 'citizen' ? 'page' : undefined} className={view === 'citizen' ? 'active' : ''} onClick={() => changeView('citizen')}>시민 검증</button><button type="button" aria-current={view === 'issuer' ? 'page' : undefined} className={view === 'issuer' ? 'active' : ''} onClick={() => changeView('issuer')}>기관 관리</button></nav></header>
    <main id="main-content">{view === 'citizen' ? <CitizenView initialText={verificationText} /> : <IssuerView onVerify={(text) => { setVerificationText(text); setView('citizen'); }} />}</main>
    <footer><span>온전 QR · 공공 안내를 더 안전하게</span><span>확인 전에는 링크를 자동으로 열지 않습니다.</span></footer>
  </div>;
}
