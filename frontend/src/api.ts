export const API_BASE = import.meta.env.DEV ? '/api' : '';

export type VerifyResult = {
  status: 'trusted' | 'blocked' | 'warning';
  reason: string;
  institution_name?: string;
  destination?: string;
  purpose?: string;
  expires_at?: number;
  qr_id?: string;
  host?: string;
  signals?: string[];
};

export function trustedHref(destination?: string): string | undefined {
  if (!destination || /[\s\\\p{Cc}\p{Cf}\p{Cs}]/u.test(destination)) return undefined;
  try {
    const url = new URL(destination);
    const domain = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
    if (url.protocol === 'https:' && domain.test(url.hostname) && !url.username && !url.password && (!url.port || url.port === '443')) return url.href;
  } catch { /* Invalid destinations never become links. */ }
  return undefined;
}

export function formatTime(value?: number | null): string {
  return value ? new Date(value * 1000).toLocaleString('ko-KR') : '기록 없음';
}

export async function checkResponse(response: Response, action: string): Promise<void> {
  if (response.ok) return;
  if (response.status === 401 || response.status === 403) throw new Error('기관 ID와 발급 토큰을 확인해 주세요. 권한이 변경됐다면 다시 연결해 주세요.');
  if (response.status === 429) throw new Error('요청이 많습니다. 잠시 뒤 다시 시도해 주세요.');
  if (response.status === 413) throw new Error('입력 내용이 너무 깁니다. 주소나 발급 목적을 줄여 주세요.');
  if (response.status === 422) {
    const body = await response.json().catch(() => ({}));
    const detail = body.detail;
    const messages: Record<string, string> = {
      'Destination must be HTTPS on an official domain': '등록된 공식 도메인의 HTTPS 주소를 입력해 주세요.',
      'Expiry must be within the next 30 days': '유효기간은 현재부터 30일 이내로 설정해 주세요.',
      'Signed QR is too long; shorten destination or purpose': 'QR에 담을 내용이 너무 깁니다. 목적지 주소나 발급 목적을 줄여 주세요.',
    };
    throw new Error(messages[detail] ?? '입력 형식을 확인해 주세요. 목적은 2자 이상이며 유효기간은 30일 이내여야 합니다.');
  }
  if (response.status === 404) throw new Error('기관 또는 QR 기록을 찾지 못했습니다. 정보를 확인하고 새로고침해 주세요.');
  if (response.status === 503) throw new Error('발급 서비스를 사용할 수 없습니다. 기관 관리자에게 문의해 주세요.');
  throw new Error(`${action} 요청을 처리하지 못했습니다. 잠시 뒤 다시 시도해 주세요.`);
}
