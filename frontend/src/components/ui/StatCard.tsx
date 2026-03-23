interface StatCardProps {
  label: string;
  value: string | number;
  delta?: number | null;
  color?: string;
  subtitle?: string;
}

export function StatCard({ label, value, delta, color, subtitle }: StatCardProps) {
  const colorStyle = color ? { color } : undefined;

  return (
    <div className="overview-stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={colorStyle}>
        {value}
        {delta != null && delta !== 0 && (
          <span className={`stat-delta delta-${delta > 0 ? 'up' : 'down'}`}>
            {delta > 0 ? '\u25B2' : '\u25BC'}&nbsp;{Math.abs(delta)}
          </span>
        )}
      </div>
      {subtitle && <div className="stat-subtitle">{subtitle}</div>}
    </div>
  );
}
