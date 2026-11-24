/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "1" = serve the MSW mock API in the browser. */
  readonly VITE_MOCK?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
