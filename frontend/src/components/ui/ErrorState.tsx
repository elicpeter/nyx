interface ErrorStateProps {
  title?: string;
  message: string;
}

export function ErrorState({ title = 'Error', message }: ErrorStateProps) {
  return (
    <div className="error-state">
      <h3>{title}</h3>
      <p>{message}</p>
    </div>
  );
}
