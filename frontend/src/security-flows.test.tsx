import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import CitizenView from './CitizenView';
import IssuerView from './IssuerView';

const scanner = vi.hoisted(() => ({ decodeFromStream: vi.fn() }));
// State/permission tests control the decoder boundary; pixel decoding is tested separately.
vi.mock('./QrReader', () => ({ QrReader: class { decodeFromStream = scanner.decodeFromStream; } }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}
function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
const trusted = {
  status: 'trusted', reason: 'valid_signature', institution_name: '검증 기관',
  purpose: '공식 안내', destination: 'https://city.example.org/notice', expires_at: 2000000000,
};
const dashboard = {
  institution: { id: 'demo-city', name: '데모 기관', official_domains: ['city.example.org'], active_key_version: 'v1' },
  qrs: [], audit: [], counts: { active: 0, revoked: 0, expired: 0, total: 0 },
};
const issued = { qr_id: 'qr-123', qr_text: 'onqr:v1:signed', qr_png_base64: 'iVBORw0KGgo=', expires_at: 2000000000 };
class FakeStream {
  stop = vi.fn();
  getTracks() { return [{ stop: this.stop }]; }
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn());
  vi.stubGlobal('MediaStream', FakeStream);
  Object.defineProperty(navigator, 'mediaDevices', { configurable: true, value: { getUserMedia: vi.fn() } });
  scanner.decodeFromStream.mockResolvedValue({ stop: vi.fn() });
});
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('시민 검증의 보안 경계', () => {
  it('서버가 trusted 상태를 보내도 실행주소·내부주소·숨은문자 주소는 링크가 되지 않으며 HTML은 문자로 표시한다', async () => {
    for (const destination of ['javascript:alert(1)', 'https://127.0.0.1/private', 'https://user:pass@city.example.org/', 'https://city.example.org/\u202eapk']) {
      vi.mocked(fetch).mockResolvedValueOnce(response({ ...trusted, destination, institution_name: '<img src=x onerror=alert(1)>' }));
      const view = render(<CitizenView />);
      fireEvent.change(screen.getByLabelText('QR 원문 또는 주소로 확인'), { target: { value: 'onqr:v1:signed' } });
      fireEvent.click(screen.getByRole('button', { name: 'QR 확인' }));
      await screen.findByRole('heading', { name: '<img src=x onerror=alert(1)>' });
      expect(screen.queryByRole('link')).toBeNull();
      expect(view.container.querySelector('img')).toBeNull();
      view.unmount();
    }
  });

  it('입력을 바꾼 뒤 도착한 이전 검증 결과로 목적지를 표시하지 않는다', async () => {
    const pending = deferred<Response>();
    vi.mocked(fetch).mockReturnValueOnce(pending.promise);
    render(<CitizenView />);
    const input = screen.getByLabelText('QR 원문 또는 주소로 확인');
    fireEvent.change(input, { target: { value: 'onqr:v1:old' } });
    fireEvent.click(screen.getByRole('button', { name: 'QR 확인' }));
    expect(fetch).toHaveBeenCalledTimes(1);
    const request = vi.mocked(fetch).mock.calls[0][1];
    fireEvent.change(input, { target: { value: 'onqr:v1:new' } });
    expect((request?.signal as AbortSignal).aborted).toBe(true);
    await act(async () => { pending.resolve(response(trusted)); await pending.promise; });
    expect(screen.queryByRole('link', { name: '공식 목적지 열기 ↗' })).toBeNull();
    expect(screen.queryByText('검증 기관')).toBeNull();
    expect(screen.getByRole('heading', { name: '아직 검증 전입니다' })).toBeTruthy();
  });

  it('검증된 QR만 링크를 제공하고 미서명 경고에는 목적지가 있어도 링크를 만들지 않는다', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(response(trusted)).mockResolvedValueOnce(response({
      status: 'warning', reason: 'unsigned_qr', destination: trusted.destination, host: 'city.example.org', signals: ['unsigned_qr'],
    }));
    render(<CitizenView />);
    const input = screen.getByLabelText('QR 원문 또는 주소로 확인');
    fireEvent.change(input, { target: { value: 'onqr:v1:signed' } });
    fireEvent.click(screen.getByRole('button', { name: 'QR 확인' }));
    const link = await screen.findByRole('link', { name: '공식 목적지 열기 ↗' });
    expect(link.getAttribute('href')).toBe(trusted.destination);
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    fireEvent.change(input, { target: { value: trusted.destination } });
    fireEvent.click(screen.getByRole('button', { name: 'QR 확인' }));
    await screen.findByRole('heading', { name: '발급기관을 확인할 수 없습니다' });
    expect(screen.queryByRole('link')).toBeNull();
    expect(String(vi.mocked(fetch).mock.calls[1][0])).toMatch(/\/analyze$/);
  });

  it.each(['stop', 'unmount'] as const)('카메라 권한 응답 전에 %s하면 나중에 받은 카메라 스트림도 종료한다', async (action) => {
    const permission = deferred<MediaStream>();
    const stream = new FakeStream();
    vi.mocked(navigator.mediaDevices.getUserMedia).mockReturnValue(permission.promise);
    const view = render(<CitizenView />);
    fireEvent.click(screen.getByRole('button', { name: '카메라로 스캔' }));
    await waitFor(() => expect(navigator.mediaDevices.getUserMedia).toHaveBeenCalledTimes(1));
    if (action === 'stop') fireEvent.click(screen.getByRole('button', { name: '카메라 끄기' }));
    else view.unmount();
    await act(async () => { permission.resolve(stream as unknown as MediaStream); await permission.promise; });
    expect(stream.stop).toHaveBeenCalledTimes(1);
    expect(scanner.decodeFromStream).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('카메라 스트림을 연 뒤 해독기 준비 중 중단하면 스트림과 늦게 도착한 해독기도 종료한다', async () => {
    const setup = deferred<{ stop: () => void }>();
    const stream = new FakeStream();
    const stopDecoder = vi.fn();
    vi.mocked(navigator.mediaDevices.getUserMedia).mockResolvedValue(stream as unknown as MediaStream);
    scanner.decodeFromStream.mockReturnValueOnce(setup.promise);
    render(<CitizenView />);
    fireEvent.click(screen.getByRole('button', { name: '카메라로 스캔' }));
    await waitFor(() => expect(scanner.decodeFromStream).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole('button', { name: '카메라 끄기' }));
    expect(stream.stop).toHaveBeenCalled();
    await act(async () => { setup.resolve({ stop: stopDecoder }); await setup.promise; });
    expect(stopDecoder).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });
});

async function connectInstitution() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText('기관 ID'), 'demo-city');
  await user.type(screen.getByLabelText('기관 발급 토큰'), 'issuer-token');
  await user.click(screen.getByRole('button', { name: '기관 연결' }));
  await screen.findByRole('heading', { name: '데모 기관' });
  return user;
}
describe('기관 관리의 요청 경합', () => {
  async function connectWithClock() {
    vi.useFakeTimers();
    vi.mocked(fetch).mockResolvedValueOnce(response(dashboard));
    render(<IssuerView onVerify={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('기관 ID'), { target: { value: 'demo-city' } });
    fireEvent.change(screen.getByLabelText('기관 발급 토큰'), { target: { value: 'issuer-token' } });
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: '기관 연결' })); });
    expect(screen.getByRole('heading', { name: '데모 기관' })).toBeTruthy();
  }

  it('5분 유휴 시 진행 요청을 중단하고 늦은 응답으로 연결을 복원하지 않는다', async () => {
    await connectWithClock();
    await act(async () => { vi.advanceTimersByTime(4 * 60000 + 50000); });
    const refreshing = deferred<Response>();
    vi.mocked(fetch).mockReturnValueOnce(refreshing.promise);
    fireEvent.click(screen.getByRole('button', { name: '새로고침' }));
    const request = vi.mocked(fetch).mock.calls[1][1];
    await act(async () => { vi.advanceTimersByTime(10000); });
    expect((request?.signal as AbortSignal).aborted).toBe(true);
    expect(screen.getByRole('heading', { name: '기관 계정 연결' })).toBeTruthy();
    expect((screen.getByLabelText('기관 발급 토큰') as HTMLInputElement).value).toBe('');
    await act(async () => { refreshing.resolve(response(dashboard)); await refreshing.promise; });
    expect(screen.queryByRole('heading', { name: '데모 기관' })).toBeNull();
  });

  it('사용자의 키 입력은 유휴 시간을 갱신하고 다시 5분 지나면 연결을 해제한다', async () => {
    await connectWithClock();
    await act(async () => { vi.advanceTimersByTime(4 * 60000); });
    fireEvent.keyDown(screen.getByLabelText('발급 목적'), { key: 'a' });
    await act(async () => { vi.advanceTimersByTime(5 * 60000 - 1); });
    expect(screen.getByRole('heading', { name: '데모 기관' })).toBeTruthy();
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(screen.getByRole('heading', { name: '기관 계정 연결' })).toBeTruthy();
  });

  it('백그라운드 타이머가 지연돼도 복귀 후 이미 만료한 연결을 입력으로 연장하지 않는다', async () => {
    await connectWithClock();
    vi.setSystemTime(Date.now() + 6 * 60000);
    fireEvent.keyDown(screen.getByLabelText('발급 목적'), { key: 'a' });
    expect(screen.getByRole('heading', { name: '기관 계정 연결' })).toBeTruthy();
    expect(screen.getByText('5분 동안 사용하지 않아 연결을 해제했습니다. 다시 연결해 주세요.')).toBeTruthy();
  });

  it('발급 버튼을 연속 작동시켜도 QR 발급 요청은 한 번만 보낸다', async () => {
    const issuing = deferred<Response>();
    vi.mocked(fetch).mockResolvedValueOnce(response(dashboard)).mockReturnValueOnce(issuing.promise).mockResolvedValueOnce(response({
      ...dashboard, counts: { active: 1, revoked: 0, expired: 0, total: 1 },
    }));
    render(<IssuerView onVerify={vi.fn()} />);
    const user = await connectInstitution();
    await user.type(screen.getByLabelText('공식 목적지'), trusted.destination);
    await user.type(screen.getByLabelText('발급 목적'), '공식 안내');
    const form = screen.getByLabelText('발급 목적').closest('form')!;
    fireEvent.submit(form);
    fireEvent.submit(form);
    const issuanceRequests = () => vi.mocked(fetch).mock.calls.filter(([url, options]) => String(url).endsWith('/qrs') && options?.method === 'POST');
    expect(issuanceRequests()).toHaveLength(1);
    expect(screen.getByRole('button', { name: '처리 중…' }).hasAttribute('disabled')).toBe(true);
    await act(async () => { issuing.resolve(response(issued, 201)); await issuing.promise; });
    await screen.findByRole('heading', { name: '발급 완료' });
    await screen.findByText('서명 QR을 발급했습니다.');
    expect(issuanceRequests()).toHaveLength(1);
  });

  it('연결을 해제한 뒤 도착한 대시보드 응답은 기관 화면을 복원하지 않는다', async () => {
    const refreshing = deferred<Response>();
    vi.mocked(fetch).mockResolvedValueOnce(response(dashboard)).mockReturnValueOnce(refreshing.promise);
    render(<IssuerView onVerify={vi.fn()} />);
    const user = await connectInstitution();
    await user.click(screen.getByRole('button', { name: '새로고침' }));
    expect(fetch).toHaveBeenCalledTimes(2);
    const request = vi.mocked(fetch).mock.calls[1][1];
    await user.click(screen.getByRole('button', { name: '연결 해제' }));
    expect((request?.signal as AbortSignal).aborted).toBe(true);
    await act(async () => { refreshing.resolve(response(dashboard)); await refreshing.promise; });
    expect(screen.queryByRole('heading', { name: '데모 기관' })).toBeNull();
    expect(screen.getByRole('heading', { name: '기관 계정 연결' })).toBeTruthy();
    expect((screen.getByLabelText('기관 발급 토큰') as HTMLInputElement).value).toBe('');
  });
});
