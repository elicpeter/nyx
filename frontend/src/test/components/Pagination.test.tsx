import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Pagination } from '@/components/ui/Pagination';

describe('Pagination', () => {
  const defaultProps = {
    page: 1,
    perPage: 50,
    total: 200,
    onPageChange: vi.fn(),
  };

  it('renders page info text', () => {
    render(<Pagination {...defaultProps} />);
    expect(screen.getByText('Page 1 of 4')).toBeInTheDocument();
  });

  it('renders total count', () => {
    render(<Pagination {...defaultProps} />);
    expect(screen.getByText('200 total')).toBeInTheDocument();
  });

  it('disables First and Prev buttons on first page', () => {
    render(<Pagination {...defaultProps} page={1} />);
    expect(screen.getByRole('button', { name: 'First' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Prev' })).toBeDisabled();
  });

  it('disables Next and Last buttons on last page', () => {
    render(<Pagination {...defaultProps} page={4} />);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Last' })).toBeDisabled();
  });

  it('enables all nav buttons on a middle page', () => {
    render(<Pagination {...defaultProps} page={2} />);
    expect(screen.getByRole('button', { name: 'First' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Prev' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Next' })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: 'Last' })).not.toBeDisabled();
  });

  it('calls onPageChange(1) when First is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} page={3} onPageChange={onPageChange} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'First' }));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it('calls onPageChange with previous page when Prev is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} page={3} onPageChange={onPageChange} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Prev' }));
    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  it('calls onPageChange with next page when Next is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} page={2} onPageChange={onPageChange} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(onPageChange).toHaveBeenCalledWith(3);
  });

  it('calls onPageChange with last page when Last is clicked', () => {
    const onPageChange = vi.fn();
    render(
      <Pagination {...defaultProps} page={2} onPageChange={onPageChange} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Last' }));
    expect(onPageChange).toHaveBeenCalledWith(4);
  });

  it('calls onPerPageChange when per-page select changes', () => {
    const onPerPageChange = vi.fn();
    render(<Pagination {...defaultProps} onPerPageChange={onPerPageChange} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: '25' } });
    expect(onPerPageChange).toHaveBeenCalledWith(25);
  });

  it('handles zero total gracefully (shows 1 of 1)', () => {
    render(<Pagination {...defaultProps} total={0} />);
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
  });

  it('shows 1 page total for total less than perPage', () => {
    render(<Pagination {...defaultProps} total={10} perPage={50} />);
    expect(screen.getByText('Page 1 of 1')).toBeInTheDocument();
  });
});
