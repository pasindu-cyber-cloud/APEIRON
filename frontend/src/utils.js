import dayjs from 'dayjs';

export function fmtBytes(n) {
  if (!n && n !== 0) return '-';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`;
}

export function fmtTime(ts) {
  if (!ts) return '-';
  return dayjs(ts).format('YYYY-MM-DD HH:mm:ss');
}

export function fmtRel(seconds) {
  if (seconds === undefined || seconds === null) return '';
  return `+${Number(seconds).toFixed(3)}s`;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_e) {
    return false;
  }
}

export function shorten(str, n = 16) {
  if (!str) return '';
  return str.length > n ? `${str.slice(0, n)}…` : str;
}
