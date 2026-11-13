// All times are the deployment's local wall clock (the same zone as chatlog
// timestamps), computed with the local `Date` fields. Around a DST change a
// wall-clock time that does not exist is rejected for one-shots, and a repeated
// hour is entered once.

const pad = (n: number): string => String(n).padStart(2, '0');

export const formatLocalDateTime = (ms: number): string => {
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

const LOCAL_DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})$/;

/** Parses `YYYY-MM-DD HH:MM` as local time; undefined if malformed or not a real wall-clock time. */
export const parseLocalDateTime = (text: string): number | undefined => {
  const m = LOCAL_DATE_TIME.exec(text.trim());
  if (!m) return undefined;
  const [year, month, day, hour, minute] = m.slice(1).map(Number) as [number, number, number, number, number];
  const d = new Date(year, month - 1, day, hour, minute, 0, 0);
  // Round trip rejects 02-30 and the nonexistent hour of a DST gap, which Date silently normalises.
  if (
    d.getFullYear() !== year
    || d.getMonth() !== month - 1
    || d.getDate() !== day
    || d.getHours() !== hour
    || d.getMinutes() !== minute
  ) return undefined;
  return d.getTime();
};

export const formatDuration = (ms: number): string => {
  const totalMin = Math.floor(ms / 60_000);
  if (totalMin < 1) return 'under a minute';
  if (totalMin < 60) return `${totalMin} min`;
  const totalHours = Math.floor(totalMin / 60);
  const min = totalMin % 60;
  if (totalHours < 24) return min === 0 ? `${totalHours} h` : `${totalHours} h ${min} min`;
  const days = Math.floor(totalHours / 24);
  const hours = totalHours % 24;
  return hours === 0 ? `${days} d` : `${days} d ${hours} h`;
};
