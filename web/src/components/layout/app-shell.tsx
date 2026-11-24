import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Bug,
  FolderGit2,
  KeyRound,
  LayoutDashboard,
  Loader2,
  Menu,
  Monitor,
  Moon,
  Play,
  Settings,
  Sun,
  Target as TargetIcon,
} from "lucide-react";
import * as React from "react";
import { activeJobsQuery } from "@/api/queries";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogTitle, SheetContent } from "@/components/ui/dialog";
import { useScanAll } from "@/features/jobs/use-scan";
import { type ThemePref, useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, exact: true },
  { to: "/findings", label: "Findings", icon: Bug, search: { status: "open" as const } },
  { to: "/repos", label: "Repos", icon: FolderGit2 },
  { to: "/targets", label: "Targets", icon: TargetIcon },
  { to: "/auth-profiles", label: "Auth profiles", icon: KeyRound },
  { to: "/scans", label: "Scans & Jobs", icon: Activity },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-0.5 p-2">
      {NAV.map((item) => (
        <Link
          key={item.to}
          to={item.to}
          search={"search" in item ? item.search : undefined}
          activeOptions={{ exact: "exact" in item, includeSearch: false }}
          onClick={onNavigate}
          className="flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-accent-foreground data-[status=active]:bg-accent data-[status=active]:text-foreground"
        >
          <item.icon aria-hidden className="size-4" />
          {item.label}
        </Link>
      ))}
    </nav>
  );
}

function Brand() {
  return (
    <Link to="/" className="flex items-center gap-2 px-4 py-4 font-semibold tracking-tight">
      <svg viewBox="0 0 32 32" className="size-6" aria-hidden>
        <rect width="32" height="32" rx="7" className="fill-slate-800 dark:fill-slate-700" />
        <path d="M16 5l9 4v6c0 6-4 10.5-9 12-5-1.5-9-6-9-12V9z" fill="none" stroke="#38bdf8" strokeWidth="2.5" strokeLinejoin="round" />
        <circle cx="16" cy="15" r="3" fill="#38bdf8" />
      </svg>
      Heimdall
    </Link>
  );
}

const THEME_NEXT: Record<ThemePref, ThemePref> = { system: "light", light: "dark", dark: "system" };
const THEME_ICON = { system: Monitor, light: Sun, dark: Moon };

function ThemeToggle() {
  const { pref, setPref } = useTheme();
  const Icon = THEME_ICON[pref];
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setPref(THEME_NEXT[pref])}
      aria-label={`Theme: ${pref}. Switch to ${THEME_NEXT[pref]}`}
      title={`Theme: ${pref}`}
    >
      <Icon aria-hidden />
    </Button>
  );
}

function ActiveJobs() {
  const { data } = useQuery(activeJobsQuery());
  const n = data?.length ?? 0;
  return (
    <Link
      to="/scans"
      search={{ tab: "jobs" }}
      className={cn(
        "inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm",
        n > 0 ? "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-100" : "text-muted-foreground",
      )}
      aria-label={`${n} active ${n === 1 ? "job" : "jobs"}`}
    >
      {n > 0 ? <Loader2 aria-hidden className="size-4 animate-spin" /> : <Activity aria-hidden className="size-4" />}
      <span className="tabular-nums">{n}</span>
      <span className="hidden sm:inline">active</span>
    </Link>
  );
}

export function AppShell() {
  const [navOpen, setNavOpen] = React.useState(false);
  const scanAll = useScanAll();
  const pathname = useRouterState({ select: (s) => s.location.pathname });
  const mainRef = React.useRef<HTMLElement>(null);

  // Move focus to the page on navigation so keyboard and screen reader users land in the content.
  const first = React.useRef(true);
  React.useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    mainRef.current?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [pathname]);

  return (
    <div className="min-h-dvh bg-background">
      <a
        href="#main"
        onClick={(e) => {
          e.preventDefault();
          mainRef.current?.focus();
        }}
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Skip to content
      </a>
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r bg-card lg:flex">
        <Brand />
        <NavLinks />
      </aside>
      <Dialog open={navOpen} onOpenChange={setNavOpen}>
        <SheetContent>
          <DialogTitle className="sr-only">Navigation</DialogTitle>
          <DialogDescription className="sr-only">Main navigation</DialogDescription>
          <Brand />
          <NavLinks onNavigate={() => setNavOpen(false)} />
        </SheetContent>
      </Dialog>
      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/95 px-3 backdrop-blur sm:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation" onClick={() => setNavOpen(true)}>
            <Menu aria-hidden />
          </Button>
          <div className="flex-1" />
          <ActiveJobs />
          <Button onClick={() => scanAll.mutate()} disabled={scanAll.isPending}>
            <Play aria-hidden /> <span>Scan all</span>
          </Button>
          <ThemeToggle />
        </header>
        <main id="main" ref={mainRef} tabIndex={-1} className="mx-auto max-w-7xl px-4 py-6 outline-none sm:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
