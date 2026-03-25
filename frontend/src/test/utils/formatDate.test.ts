import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatShortDate, relTime } from '../../utils/formatDate';

describe('formatShortDate', () => {
  it('returns empty string for null', () => {
    expect(formatShortDate(null)).toBe('');
  });

  it('returns empty string for undefined', () => {
    expect(formatShortDate(undefined)).toBe('');
  });

  it('returns empty string for empty string', () => {
    expect(formatShortDate('')).toBe('');
  });

  it('formats a valid ISO date string with M/D H:MM pattern', () => {
    const result = formatShortDate('2024-06-15T14:05:00.000Z');
    expect(result).toMatch(/^\d+\/\d+ \d+:\d{2}$/);
  });

  it('zero-pads minutes to two digits', () => {
    const d = new Date(2024, 0, 1, 10, 5, 0);
    const result = formatShortDate(d.toISOString());
    expect(result).toMatch(/:05$/);
  });

  it('does not zero-pad double-digit minutes', () => {
    const d = new Date(2024, 0, 1, 10, 30, 0);
    const result = formatShortDate(d.toISOString());
    expect(result).toMatch(/:30$/);
  });
});

describe('relTime', () => {
  let now: number;

  beforeEach(() => {
    now = Date.now();
    vi.useFakeTimers();
    vi.setSystemTime(now);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns empty string for null', () => {
    expect(relTime(null)).toBe('');
  });

  it('returns empty string for undefined', () => {
    expect(relTime(undefined)).toBe('');
  });

  it('returns empty string for empty string', () => {
    expect(relTime('')).toBe('');
  });

  it('returns "just now" for a future date', () => {
    const future = new Date(now + 5000).toISOString();
    expect(relTime(future)).toBe('just now');
  });

  it('returns "just now" for 0 seconds ago', () => {
    expect(relTime(new Date(now).toISOString())).toBe('just now');
  });

  it('returns "just now" for 1 second ago', () => {
    expect(relTime(new Date(now - 1000).toISOString())).toBe('just now');
  });

  it('returns "Xs ago" for less than 60 seconds', () => {
    expect(relTime(new Date(now - 30 * 1000).toISOString())).toBe('30s ago');
  });

  it('returns "1 minute ago" for exactly 60 seconds', () => {
    expect(relTime(new Date(now - 60 * 1000).toISOString())).toBe(
      '1 minute ago',
    );
  });

  it('returns "X minutes ago" for less than 60 minutes', () => {
    expect(relTime(new Date(now - 5 * 60 * 1000).toISOString())).toBe(
      '5 minutes ago',
    );
  });

  it('returns "1 hour ago" for exactly 1 hour', () => {
    expect(relTime(new Date(now - 60 * 60 * 1000).toISOString())).toBe(
      '1 hour ago',
    );
  });

  it('returns "X hours ago" for less than 24 hours', () => {
    expect(relTime(new Date(now - 5 * 60 * 60 * 1000).toISOString())).toBe(
      '5 hours ago',
    );
  });

  it('returns "1 day ago" for exactly 1 day', () => {
    expect(relTime(new Date(now - 24 * 60 * 60 * 1000).toISOString())).toBe(
      '1 day ago',
    );
  });

  it('returns "X days ago" for less than 30 days', () => {
    expect(
      relTime(new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString()),
    ).toBe('10 days ago');
  });

  it('returns "1 month ago" for ~30 days', () => {
    expect(
      relTime(new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString()),
    ).toBe('1 month ago');
  });

  it('returns "X months ago" for less than 12 months', () => {
    expect(
      relTime(new Date(now - 6 * 30 * 24 * 60 * 60 * 1000).toISOString()),
    ).toBe('6 months ago');
  });

  it('returns "1 year ago" for ~12 months', () => {
    expect(
      relTime(new Date(now - 12 * 30 * 24 * 60 * 60 * 1000).toISOString()),
    ).toBe('1 year ago');
  });

  it('returns "X years ago" for multiple years', () => {
    expect(
      relTime(new Date(now - 2 * 12 * 30 * 24 * 60 * 60 * 1000).toISOString()),
    ).toBe('2 years ago');
  });
});
