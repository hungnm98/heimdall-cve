import type { QueryClient } from "@tanstack/react-query";
import {
  createHashHistory,
  createRootRouteWithContext,
  createRoute,
  createRouter,
  Link,
  type RouterHistory,
} from "@tanstack/react-router";
import type { JobStatus } from "@/api/types";
import { EmptyState } from "@/components/common";
import { AppShell } from "@/components/layout/app-shell";
import { Button } from "@/components/ui/button";
import { AuthProfilesPage } from "@/features/auth-profiles/auth-profiles-page";
import { DashboardPage } from "@/features/dashboard/dashboard-page";
import { FindingDetailPage } from "@/features/findings/finding-detail-page";
import { parseFindingSearch } from "@/features/findings/filters";
import { FindingsPage } from "@/features/findings/findings-page";
import { JobDetailPage } from "@/features/jobs/job-detail-page";
import { RepoDetailPage } from "@/features/repos/repo-detail-page";
import { ReposPage } from "@/features/repos/repos-page";
import { RunDetailPage } from "@/features/scans/run-detail-page";
import { ScansPage } from "@/features/scans/scans-page";
import { SettingsPage } from "@/features/settings/settings-page";
import { TargetFormPage } from "@/features/targets/target-form-page";
import { TargetsPage } from "@/features/targets/targets-page";

const str = (v: unknown) => (typeof v === "string" && v.trim() !== "" ? v : typeof v === "number" ? String(v) : undefined);
const JOB_STATUSES: JobStatus[] = ["queued", "running", "succeeded", "failed", "canceled"];

function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      description="The page you are looking for does not exist."
      action={
        <Button asChild variant="outline">
          <Link to="/">Back to the dashboard</Link>
        </Button>
      }
    />
  );
}

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: AppShell,
  notFoundComponent: NotFound,
});

const dashboardRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: DashboardPage });

const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/findings",
  validateSearch: parseFindingSearch,
  component: FindingsPage,
});

const findingRoute = createRoute({ getParentRoute: () => rootRoute, path: "/findings/$id", component: FindingDetailPage });

const reposRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/repos",
  validateSearch: (s: Record<string, unknown>): { q?: string } => ({ q: str(s.q) }),
  component: ReposPage,
});

const repoRoute = createRoute({ getParentRoute: () => rootRoute, path: "/repos/$owner/$name", component: RepoDetailPage });

const targetsRoute = createRoute({ getParentRoute: () => rootRoute, path: "/targets", component: TargetsPage });
const targetNewRoute = createRoute({ getParentRoute: () => rootRoute, path: "/targets/new", component: TargetFormPage });
const targetEditRoute = createRoute({ getParentRoute: () => rootRoute, path: "/targets/$id", component: TargetFormPage });

const authProfilesRoute = createRoute({ getParentRoute: () => rootRoute, path: "/auth-profiles", component: AuthProfilesPage });

const scansRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/scans",
  validateSearch: (s: Record<string, unknown>): { tab?: "runs" | "jobs"; status?: JobStatus } => ({
    tab: s.tab === "jobs" ? "jobs" : s.tab === "runs" ? "runs" : undefined,
    status: JOB_STATUSES.find((x) => x === s.status),
  }),
  component: ScansPage,
});

const runRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/runs/$id",
  validateSearch: (s: Record<string, unknown>): { against?: number } => {
    const n = Number(s.against);
    return { against: Number.isInteger(n) && n > 0 ? n : undefined };
  },
  component: RunDetailPage,
});

const jobRoute = createRoute({ getParentRoute: () => rootRoute, path: "/jobs/$id", component: JobDetailPage });

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  validateSearch: (s: Record<string, unknown>): { tab?: "sources" | "notifiers" | "audit" } => ({
    tab: s.tab === "notifiers" || s.tab === "audit" || s.tab === "sources" ? s.tab : undefined,
  }),
  component: SettingsPage,
});

export const routeTree = rootRoute.addChildren([
  dashboardRoute,
  findingsRoute,
  findingRoute,
  reposRoute,
  repoRoute,
  targetsRoute,
  targetNewRoute,
  targetEditRoute,
  authProfilesRoute,
  scansRoute,
  runRoute,
  jobRoute,
  settingsRoute,
]);

/**
 * Hash history: the bundle uses relative asset URLs (vite `base: "./"`), so deep
 * links must not change the document path. This also means the SPA works under
 * any path prefix without server-side fallback rules.
 */
export function createAppRouter(queryClient: QueryClient, history: RouterHistory = createHashHistory()) {
  return createRouter({
    routeTree,
    history,
    context: { queryClient },
    defaultPreload: "intent",
    defaultPreloadStaleTime: 0,
    scrollRestoration: true,
  });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
