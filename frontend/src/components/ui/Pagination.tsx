interface PaginationProps {
  page: number;
  perPage: number;
  total: number;
  onPageChange: (page: number) => void;
  onPerPageChange?: (perPage: number) => void;
}

const PER_PAGE_OPTIONS = [25, 50, 100];

export function Pagination({
  page,
  perPage,
  total,
  onPageChange,
  onPerPageChange,
}: PaginationProps) {
  const totalPages = Math.ceil(total / perPage) || 1;

  return (
    <div className="pagination">
      <div className="pagination-left">
        <span>Per page:</span>
        <select
          value={perPage}
          onChange={(e) => onPerPageChange?.(Number(e.target.value))}
        >
          {PER_PAGE_OPTIONS.map((n) => (
            <option key={n} value={n}>
              {n}
            </option>
          ))}
        </select>
      </div>

      <div className="pagination-center">
        <button
          className="btn btn-sm"
          disabled={page <= 1}
          onClick={() => onPageChange(1)}
        >
          First
        </button>
        <button
          className="btn btn-sm"
          disabled={page <= 1}
          onClick={() => onPageChange(Math.max(1, page - 1))}
        >
          Prev
        </button>
        <span>
          Page {page} of {totalPages}
        </span>
        <button
          className="btn btn-sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
        >
          Next
        </button>
        <button
          className="btn btn-sm"
          disabled={page >= totalPages}
          onClick={() => onPageChange(totalPages)}
        >
          Last
        </button>
      </div>

      <div className="pagination-right">
        <span>{total} total</span>
      </div>
    </div>
  );
}
