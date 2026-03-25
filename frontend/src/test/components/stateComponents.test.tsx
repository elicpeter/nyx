import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { LoadingState } from '@/components/ui/LoadingState';

describe('EmptyState', () => {
  it('renders a message when provided', () => {
    render(<EmptyState message="Nothing here" />);
    expect(screen.getByText('Nothing here')).toBeInTheDocument();
  });

  it('renders children when provided', () => {
    render(
      <EmptyState>
        <button>Add item</button>
      </EmptyState>,
    );
    expect(
      screen.getByRole('button', { name: 'Add item' }),
    ).toBeInTheDocument();
  });

  it('renders an icon when provided', () => {
    render(<EmptyState icon={<span data-testid="icon" />} />);
    expect(screen.getByTestId('icon')).toBeInTheDocument();
  });

  it('renders nothing extra when no props are given', () => {
    const { container } = render(<EmptyState />);
    const root = container.firstChild as HTMLElement;
    // Only the wrapper div should exist with no visible content
    expect(root.childElementCount).toBe(0);
  });
});

describe('ErrorState', () => {
  it('renders the error message', () => {
    render(<ErrorState message="Something went wrong" />);
    expect(screen.getByText('Something went wrong')).toBeInTheDocument();
  });

  it('renders the default title "Error"', () => {
    render(<ErrorState message="Oops" />);
    expect(screen.getByRole('heading', { name: 'Error' })).toBeInTheDocument();
  });

  it('renders a custom title when provided', () => {
    render(<ErrorState title="Network Error" message="Timeout" />);
    expect(
      screen.getByRole('heading', { name: 'Network Error' }),
    ).toBeInTheDocument();
  });
});

describe('LoadingState', () => {
  it('renders the default "Loading..." message', () => {
    render(<LoadingState />);
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('renders a custom message when provided', () => {
    render(<LoadingState message="Fetching data…" />);
    expect(screen.getByText('Fetching data…')).toBeInTheDocument();
  });
});
