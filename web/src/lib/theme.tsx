import * as React from "react";

export type ThemePref = "system" | "light" | "dark";
const KEY = "heimdall.theme";

function readPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    // storage unavailable (private mode): fall back to system
  }
  return "system";
}

function systemDark() {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function apply(pref: ThemePref): "light" | "dark" {
  const resolved = pref === "system" ? (systemDark() ? "dark" : "light") : pref;
  document.documentElement.classList.toggle("dark", resolved === "dark");
  return resolved;
}

/** Applies the stored theme before React renders, to avoid a flash. */
export function initTheme() {
  apply(readPref());
}

interface ThemeCtx {
  pref: ThemePref;
  resolved: "light" | "dark";
  setPref: (p: ThemePref) => void;
}

const Ctx = React.createContext<ThemeCtx>({ pref: "system", resolved: "light", setPref: () => {} });

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [pref, setPrefState] = React.useState<ThemePref>(readPref);
  const [resolved, setResolved] = React.useState<"light" | "dark">(() => apply(pref));

  React.useEffect(() => {
    setResolved(apply(pref));
    if (pref !== "system" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => setResolved(apply("system"));
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [pref]);

  const setPref = React.useCallback((p: ThemePref) => {
    try {
      localStorage.setItem(KEY, p);
    } catch {
      // ignore
    }
    setPrefState(p);
  }, []);

  const value = React.useMemo(() => ({ pref, resolved, setPref }), [pref, resolved, setPref]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTheme() {
  return React.useContext(Ctx);
}
