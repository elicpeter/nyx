import { QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { queryClient } from './api/queryClient';
import { SSEProvider } from './contexts/SSEContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { ToastProvider } from './contexts/ToastContext';
import { Toaster } from './components/ui/Toaster';
import { AppLayout } from './components/layout/AppLayout';

export function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <SSEProvider>
            <BrowserRouter>
              <AppLayout />
              <Toaster />
            </BrowserRouter>
          </SSEProvider>
        </ToastProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
