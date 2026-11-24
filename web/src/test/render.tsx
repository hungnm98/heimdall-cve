import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import type * as React from "react";
import { App } from "@/app";

export function testQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
}

/** Renders the whole app (router + query client) at `path`; returns the history to inspect the URL. */
export function renderApp(path: string) {
  const history = createMemoryHistory({ initialEntries: [path] });
  const utils = render(<App queryClient={testQueryClient()} history={history} />);
  return { ...utils, history };
}

/** Renders a component that only needs React Query. */
export function renderWithQuery(ui: React.ReactElement) {
  return render(<QueryClientProvider client={testQueryClient()}>{ui}</QueryClientProvider>);
}
