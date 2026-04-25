import { QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { queryClient } from './api/queryClient';
import { SSEProvider } from './contexts/SSEContext';
import { AppLayout } from './components/layout/AppLayout';

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <SSEProvider>
        <BrowserRouter>
          <AppLayout />
        </BrowserRouter>
      </SSEProvider>
    </QueryClientProvider>
  );
}
