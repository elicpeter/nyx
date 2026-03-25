import { describe, it, expect } from 'vitest';
import {
  getNodeStyle,
  getEdgeStyle,
} from '@/components/debug/graph/nodeStyles';

describe('getNodeStyle', () => {
  it('returns a style for Entry nodes', () => {
    const s = getNodeStyle('Entry');
    expect(s.fill).toBe('#22c55e');
    expect(s.shape).toBe('double');
  });

  it('returns a style for Exit nodes', () => {
    const s = getNodeStyle('Exit');
    expect(s.shape).toBe('double');
  });

  it('returns a style for If nodes', () => {
    const s = getNodeStyle('If');
    expect(s.shape).toBe('rect');
    expect(s.textFill).toBe('#fff');
  });

  it('returns a style for Loop nodes', () => {
    const s = getNodeStyle('Loop');
    expect(s.shape).toBe('rect');
  });

  it('returns a style for Call nodes', () => {
    const s = getNodeStyle('Call');
    expect(s.shape).toBe('rect');
  });

  it('returns a terminal shape for Return nodes', () => {
    const s = getNodeStyle('Return');
    expect(s.shape).toBe('terminal');
  });

  it('returns the default style for unknown node types', () => {
    const s = getNodeStyle('Unknown');
    expect(s.fill).toBe('#e5e7eb');
    expect(s.shape).toBe('rect');
  });

  it('default style has correct text color', () => {
    const s = getNodeStyle('Stmt');
    expect(s.textFill).toBe('#374151');
  });
});

describe('getEdgeStyle', () => {
  it('returns green color for True edges', () => {
    const s = getEdgeStyle('True');
    expect(s.color).toBe('#22c55e');
    expect(s.dash).toBe('');
  });

  it('returns red color for False edges', () => {
    const s = getEdgeStyle('False');
    expect(s.color).toBe('#ef4444');
    expect(s.dash).toBe('');
  });

  it('returns dashed style for Back edges', () => {
    const s = getEdgeStyle('Back');
    expect(s.color).toBe('#a855f7');
    expect(s.dash).toBe('6 3');
  });

  it('returns dashed style for Exception edges', () => {
    const s = getEdgeStyle('Exception');
    expect(s.dash).toBe('3 3');
  });

  it('returns default style for Seq edges', () => {
    const s = getEdgeStyle('Seq');
    expect(s.color).toBe('#9ca3af');
    expect(s.dash).toBe('');
  });

  it('returns default style for unknown edge types', () => {
    const s = getEdgeStyle('Whatever');
    expect(s.color).toBe('#9ca3af');
  });
});
