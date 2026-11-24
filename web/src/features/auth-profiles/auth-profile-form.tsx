import { KeyRound } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { splitFieldErrors } from "@/api/problem";
import { useSaveAuthProfile } from "@/api/queries";
import type { AuthProfile, AuthProfileInput } from "@/api/types";
import { Field, InlineError } from "@/components/common";
import { Button } from "@/components/ui/button";
import { DialogFooter } from "@/components/ui/dialog";
import { Input, NativeSelect, Textarea } from "@/components/ui/input";

type ProfileType = AuthProfileInput["type"];

const SECRET_KIND: Record<ProfileType, NonNullable<AuthProfileInput["secret_kind"]>> = {
  token: "token",
  app: "private_key",
  ssh: "ssh_key",
};

const SECRET_LABEL: Record<ProfileType, string> = {
  token: "Personal access token",
  app: "GitHub App private key (PEM)",
  ssh: "SSH private key",
};

const FIELDS = ["name", "type", "secret", "secret_kind", "options", "options.app_id", "options.installation_id", "options.known_hosts", "options.base_url"];

interface State {
  name: string;
  type: ProfileType;
  app_id: string;
  installation_id: string;
  known_hosts: string;
  base_url: string;
  secret: string;
}

function initial(p?: AuthProfile): State {
  const o = (p?.options ?? {}) as Record<string, unknown>;
  const s = (k: string) => (o[k] === undefined || o[k] === null ? "" : String(o[k]));
  return {
    name: p?.name ?? "",
    type: (p?.type as ProfileType) ?? "token",
    app_id: s("app_id"),
    installation_id: s("installation_id"),
    known_hosts: s("known_hosts"),
    base_url: s("base_url"),
    // Secrets are write-only: never pre-filled.
    secret: "",
  };
}

/** Builds the request body. An empty secret is omitted so the server keeps the current one. */
export function toProfileInput(s: State, secretsEnabled: boolean): AuthProfileInput {
  const options: Record<string, unknown> = {};
  if (s.base_url.trim()) options.base_url = s.base_url.trim();
  if (s.type === "app") {
    if (s.app_id.trim()) options.app_id = /^\d+$/.test(s.app_id.trim()) ? Number(s.app_id.trim()) : s.app_id.trim();
    if (s.installation_id.trim())
      options.installation_id = /^\d+$/.test(s.installation_id.trim()) ? Number(s.installation_id.trim()) : s.installation_id.trim();
  }
  if (s.type === "ssh" && s.known_hosts.trim()) options.known_hosts = s.known_hosts.trim();
  const body: AuthProfileInput = { name: s.name.trim(), type: s.type, options };
  if (secretsEnabled && s.secret.trim() !== "") {
    body.secret = s.type === "token" ? s.secret.trim() : s.secret;
    body.secret_kind = SECRET_KIND[s.type];
  }
  return body;
}

export function AuthProfileForm({
  profile,
  secretsEnabled,
  onDone,
  onCancel,
}: {
  profile?: AuthProfile;
  secretsEnabled: boolean;
  onDone: (p: AuthProfile) => void;
  onCancel: () => void;
}) {
  const editing = profile !== undefined;
  const [s, setS] = React.useState<State>(() => initial(profile));
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const save = useSaveAuthProfile();
  const set = <K extends keyof State>(k: K, v: State[K]) => setS((p) => ({ ...p, [k]: v }));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!editing && !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(s.name.trim()))
      errs.name = "Lowercase letters, digits, - and _; must start with a letter or digit.";
    if (s.type === "app" && !s.app_id.trim()) errs["options.app_id"] = "Required for a GitHub App.";
    if (s.type === "app" && !s.installation_id.trim()) errs["options.installation_id"] = "Required for a GitHub App.";
    if (!editing && secretsEnabled && s.secret.trim() === "") errs.secret = "Enter the secret for the new profile.";
    setErrors(errs);
    if (Object.keys(errs).length) return;
    save.mutate(
      { name: profile?.name, body: toProfileInput(s, secretsEnabled) },
      {
        onSuccess: (p) => {
          toast.success(editing ? `Saved ${p.name}` : `Created ${p.name}`);
          setS((x) => ({ ...x, secret: "" }));
          onDone(p);
        },
        onError: (err) => setErrors(splitFieldErrors(err, FIELDS).fields),
      },
    );
  };

  const unmapped = save.isError && Object.keys(splitFieldErrors(save.error, FIELDS).fields).length === 0;

  return (
    <form onSubmit={submit} noValidate className="grid gap-4" autoComplete="off">
      <Field id="ap-name" label="Name" error={errors.name} hint={editing ? "The name identifies the profile and cannot be changed." : "Referenced by targets, e.g. github-token."}>
        <Input value={s.name} onChange={(e) => set("name", e.target.value)} disabled={editing} placeholder="github-token" />
      </Field>
      <Field id="ap-type" label="Type" error={errors.type}>
        <NativeSelect value={s.type} onChange={(e) => set("type", e.target.value as ProfileType)}>
          <option value="token">Token (PAT / fine-grained)</option>
          <option value="app">GitHub App</option>
          <option value="ssh">SSH key</option>
        </NativeSelect>
      </Field>
      {s.type === "app" ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="ap-app_id" label="App ID" error={errors["options.app_id"]}>
            <Input inputMode="numeric" value={s.app_id} onChange={(e) => set("app_id", e.target.value)} />
          </Field>
          <Field id="ap-installation_id" label="Installation ID" error={errors["options.installation_id"]}>
            <Input inputMode="numeric" value={s.installation_id} onChange={(e) => set("installation_id", e.target.value)} />
          </Field>
        </div>
      ) : null}
      {s.type === "ssh" ? (
        <Field id="ap-known_hosts" label="known_hosts entries" error={errors["options.known_hosts"]} hint="Optional. Pins the host keys instead of trusting the system known_hosts.">
          <Textarea value={s.known_hosts} onChange={(e) => set("known_hosts", e.target.value)} className="font-mono text-xs" placeholder="github.com ssh-ed25519 AAAA…" />
        </Field>
      ) : null}
      {s.type !== "ssh" ? (
        <Field id="ap-base_url" label="API base URL" error={errors["options.base_url"]} hint="Only for GitHub Enterprise Server.">
          <Input value={s.base_url} onChange={(e) => set("base_url", e.target.value)} placeholder="https://github.example.com/api/v3" />
        </Field>
      ) : null}

      {secretsEnabled ? (
        <Field
          id="ap-secret"
          label={
            <span className="inline-flex items-center gap-1">
              <KeyRound aria-hidden className="size-3.5" /> {SECRET_LABEL[s.type]}
            </span>
          }
          error={errors.secret}
          hint={
            editing
              ? profile?.has_secret
                ? `Write-only. Current secret: ${profile.secret_fingerprint ?? "set"}. Leave empty to keep the current secret.`
                : "Write-only. No secret is stored yet."
              : "Write-only: stored encrypted and never shown again."
          }
        >
          {s.type === "token" ? (
            <Input
              type="password"
              value={s.secret}
              onChange={(e) => set("secret", e.target.value)}
              placeholder={editing ? "Leave empty to keep the current secret" : "ghp_…"}
              autoComplete="new-password"
              spellCheck={false}
            />
          ) : (
            <Textarea
              rows={5}
              className="font-mono text-xs"
              value={s.secret}
              onChange={(e) => set("secret", e.target.value)}
              placeholder={editing ? "Leave empty to keep the current secret" : "-----BEGIN … PRIVATE KEY-----"}
              autoComplete="off"
              spellCheck={false}
            />
          )}
        </Field>
      ) : (
        <p className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100">
          Entering secrets in the UI is disabled because the server has no master key (<code>HEIMDALL_MASTER_KEY</code>). Configure a master key, or reference the secret from the config file (<code>token_env</code> / <code>token_file</code>).
        </p>
      )}
      {unmapped ? <InlineError error={save.error} /> : null}
      <DialogFooter>
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? "Saving…" : editing ? "Save changes" : "Create profile"}
        </Button>
      </DialogFooter>
    </form>
  );
}
