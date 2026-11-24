import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, type RouterHistory } from "@tanstack/react-router";
import * as React from "react";
import { ApiError } from "@/api/problem";
import { Toaster } from "@/components/ui/sonner";
import { ThemeProvider } from "@/lib/theme";
import { createAppRouter } from "@/router";

export function createQueryClient() {
  return new QueryClient({
    queryCache: new QueryCache(),
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: true,
        // Don't hammer the server on client errors (404, 400…).
        retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
      },
    },
  });
}

export function App({ queryClient, history }: { queryClient?: QueryClient; history?: RouterHistory }) {
  const [qc] = React.useState(() => queryClient ?? createQueryClient());
  const [router] = React.useState(() => createAppRouter(qc, history));
  return (
    <ThemeProvider>
      <QueryClientProvider client={qc}>
        <RouterProvider router={router} />
        <Toaster />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
