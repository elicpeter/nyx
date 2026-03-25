import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { StatCard } from '@/components/ui/StatCard';

describe('StatCard', () => {
  it('renders the label', () => {
    render(<StatCard label="Total Findings" value={42} />);
    expect(screen.getByText('Total Findings')).toBeInTheDocument();
  });

  it('renders a numeric value', () => {
    render(<StatCard label="Count" value={100} />);
    expect(screen.getByText('100')).toBeInTheDocument();
  });

  it('renders a string value', () => {
    render(<StatCard label="Status" value="active" />);
    expect(screen.getByText('active')).toBeInTheDocument();
  });

  it('renders a subtitle when provided', () => {
    render(<StatCard label="Scans" value={5} subtitle="last 7 days" />);
    expect(screen.getByText('last 7 days')).toBeInTheDocument();
  });

  it('does not render a subtitle element when omitted', () => {
    render(<StatCard label="Scans" value={5} />);
    expect(screen.queryByText('last 7 days')).not.toBeInTheDocument();
  });

  it('applies the color style when provided', () => {
    render(<StatCard label="Critical" value={3} color="#ef4444" />);
    const valueEl = screen.getByText('3');
    expect(valueEl).toHaveStyle({ color: '#ef4444' });
  });

  it('shows an up arrow delta for positive values', () => {
    render(<StatCard label="New" value={10} delta={3} />);
    // ▲ character followed by the number
    expect(screen.getByText(/▲/)).toBeInTheDocument();
    expect(screen.getByText(/3/)).toBeInTheDocument();
  });

  it('shows a down arrow delta for negative values', () => {
    render(<StatCard label="Resolved" value={8} delta={-2} />);
    expect(screen.getByText(/▼/)).toBeInTheDocument();
  });

  it('does not render a delta when delta is 0', () => {
    const { container } = render(<StatCard label="Same" value={5} delta={0} />);
    expect(container.querySelector('.stat-delta')).not.toBeInTheDocument();
  });

  it('does not render a delta when delta is null', () => {
    const { container } = render(
      <StatCard label="Same" value={5} delta={null} />,
    );
    expect(container.querySelector('.stat-delta')).not.toBeInTheDocument();
  });

  it('does not render a delta when delta is omitted', () => {
    const { container } = render(<StatCard label="Same" value={5} />);
    expect(container.querySelector('.stat-delta')).not.toBeInTheDocument();
  });
});
