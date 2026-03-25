import { describe, it, expect } from 'vitest';
import { truncPath } from '../../utils/truncPath';

describe('truncPath', () => {
  it('returns empty string for null', () => {
    expect(truncPath(null)).toBe('');
  });

  it('returns empty string for undefined', () => {
    expect(truncPath(undefined)).toBe('');
  });

  it('returns path unchanged when shorter than maxLen', () => {
    expect(truncPath('src/foo.ts')).toBe('src/foo.ts');
  });

  it('returns path unchanged when equal to maxLen', () => {
    const p = 'a'.repeat(60);
    expect(truncPath(p)).toBe(p);
  });

  it('truncates a long path with leading "..."', () => {
    const p = '/very/long/path/that/exceeds/the/default/max/length/limit/file.ts';
    const result = truncPath(p);
    expect(result.startsWith('...')).toBe(true);
    expect(result.length).toBe(60);
  });

  it('keeps the tail of the path after truncation', () => {
    const p = '/very/long/path/that/exceeds/the/default/max/length/limit/file.ts';
    const result = truncPath(p);
    expect(result.endsWith('file.ts')).toBe(true);
  });

  it('respects a custom maxLen', () => {
    const p = '/some/path/to/a/file.ts';
    const result = truncPath(p, 10);
    expect(result.length).toBe(10);
    expect(result.startsWith('...')).toBe(true);
  });

  it('returns path unchanged when shorter than custom maxLen', () => {
    expect(truncPath('short.ts', 20)).toBe('short.ts');
  });
});
