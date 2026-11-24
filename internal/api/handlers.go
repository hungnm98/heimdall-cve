package api

import (
	"net/http"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/service"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

func (h *handler) getMeta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, metaDTO{
		Version: h.opts.Version, SecretsEnabled: h.s.AuthProfiles.SecretsEnabled(), JobsBackend: h.opts.JobsBackend,
		Providers: nonNil(h.opts.Providers), AuthTypes: nonNil(h.opts.AuthTypes),
	})
}

func (h *handler) getDashboard(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	n := int(q.int64("trend_runs"))
	if !q.ok(w) {
		return
	}
	sum, err := h.s.Dashboard.Summary(r.Context(), n)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDashboard(sum))
}

// ---- targets ----

func (h *handler) listTargets(w http.ResponseWriter, r *http.Request) {
	ts, err := h.s.Targets.List(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(ts, "", toTarget))
}

func (h *handler) createTarget(w http.ResponseWriter, r *http.Request) {
	var in targetInputDTO
	if !decode(w, r, &in) {
		return
	}
	t, err := h.s.Targets.Create(r.Context(), actorFrom(r.Context()), in.toService())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toTarget(*t))
}

func (h *handler) previewTarget(w http.ResponseWriter, r *http.Request) {
	var in targetInputDTO
	if !decode(w, r, &in) {
		return
	}
	repos, err := h.s.Targets.Preview(r.Context(), in.toService())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(repos, "", toRepo))
}

func (h *handler) getTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, err := h.s.Targets.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTarget(*t))
}

func (h *handler) updateTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in targetInputDTO
	if !decode(w, r, &in) {
		return
	}
	t, err := h.s.Targets.Update(r.Context(), actorFrom(r.Context()), id, in.toService())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTarget(*t))
}

func (h *handler) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.s.Targets.Delete(r.Context(), actorFrom(r.Context()), id); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- auth profiles ----

// usedBy maps profile names to the ids of targets using them.
func (h *handler) usedBy(r *http.Request) (map[string][]int64, error) {
	ts, err := h.s.Targets.List(r.Context())
	if err != nil {
		return nil, err
	}
	out := map[string][]int64{}
	for _, t := range ts {
		out[t.Auth] = append(out[t.Auth], t.ID)
		if t.ListAuth != "" && t.ListAuth != t.Auth {
			out[t.ListAuth] = append(out[t.ListAuth], t.ID)
		}
	}
	return out, nil
}

func (h *handler) profileResponse(w http.ResponseWriter, r *http.Request, status int, p *model.AuthProfile) {
	used, err := h.usedBy(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, status, toAuthProfile(*p, used[p.Name]))
}

func (h *handler) listAuthProfiles(w http.ResponseWriter, r *http.Request) {
	ps, err := h.s.AuthProfiles.List(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	used, err := h.usedBy(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(ps, "", func(p model.AuthProfile) authProfileDTO { return toAuthProfile(p, used[p.Name]) }))
}

func (h *handler) createAuthProfile(w http.ResponseWriter, r *http.Request) {
	var in authProfileInputDTO
	if !decode(w, r, &in) {
		return
	}
	p, err := h.s.AuthProfiles.Create(r.Context(), actorFrom(r.Context()), in.toService())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.profileResponse(w, r, http.StatusCreated, p)
}

func (h *handler) updateAuthProfile(w http.ResponseWriter, r *http.Request) {
	var in authProfileInputDTO
	if !decode(w, r, &in) {
		return
	}
	p, err := h.s.AuthProfiles.Update(r.Context(), actorFrom(r.Context()), r.PathValue("name"), in.toService())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.profileResponse(w, r, http.StatusOK, p)
}

func (h *handler) deleteAuthProfile(w http.ResponseWriter, r *http.Request) {
	if err := h.s.AuthProfiles.Delete(r.Context(), actorFrom(r.Context()), r.PathValue("name")); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) testAuthProfile(w http.ResponseWriter, r *http.Request) {
	res, err := h.s.AuthProfiles.Test(r.Context(), r.PathValue("name"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, connectionTestDTO{OK: res.OK, Message: res.Message})
}

// ---- repos ----

func (h *handler) listRepos(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	f := store.RepoFilter{TargetID: q.int64("target_id"), Query: q.str("q"), After: q.str("cursor"), Limit: q.limit(),
		Sort: store.RepoSort(q.str("sort")), Order: store.SortOrder(q.str("order"))}
	if !q.ok(w) {
		return
	}
	page, err := h.s.Repos.List(r.Context(), f)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(page.Items, page.NextCursor, toRepoRecord))
}

func (h *handler) getRepo(w http.ResponseWriter, r *http.Request) {
	d, err := h.s.Repos.Get(r.Context(), r.PathValue("owner")+"/"+r.PathValue("name"), r.URL.Query().Get("branch"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRepoDetail(d))
}

// ---- findings ----

func (h *handler) listFindings(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	f := store.FindingFilter{
		Repo: q.str("repo"), Kind: model.FindingKind(q.str("kind")), Status: model.FindingStatus(q.str("status")),
		InKEV: q.bool("kev"), NewSince: q.time("new_since"), Query: strings.TrimSpace(q.str("q")),
		Branch: q.str("branch"), DefaultBranchOnly: q.bool("primary_branch"),
		Sort: store.FindingSort(q.str("sort")), Order: store.SortOrder(q.str("order")),
		After: q.str("cursor"), Limit: q.limit(),
	}
	if v := q.str("min_severity"); v != "" {
		if sev := model.ParseSeverity(v); sev != model.SeverityUnknown || strings.EqualFold(v, "UNKNOWN") {
			f.MinSeverity = sev
		} else {
			q.fields["min_severity"] = "must be CRITICAL, HIGH, MEDIUM, LOW or UNKNOWN"
		}
	}
	if !oneOf(string(f.Kind), "dependency", "runtime", "code", "secret", "config") {
		q.fields["kind"] = "unknown finding kind"
	}
	if !oneOf(string(f.Status), "open", "fixed", "suppressed", "removed") {
		q.fields["status"] = "must be open, fixed, suppressed or removed"
	}
	if f.Branch != "" && f.DefaultBranchOnly {
		q.fields["branch"] = "branch and primary_branch are exclusive"
	}
	if !q.ok(w) {
		return
	}
	page, err := h.s.Findings.List(r.Context(), f)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(page.Items, page.NextCursor, toFinding))
}

// oneOf reports whether v is empty or one of allowed.
func oneOf(v string, allowed ...string) bool {
	if v == "" {
		return true
	}
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func (h *handler) getFinding(w http.ResponseWriter, r *http.Request) {
	d, err := h.s.Findings.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toFindingDetail(d))
}

func (h *handler) suppressFinding(w http.ResponseWriter, r *http.Request) {
	var in suppressInputDTO
	if !decode(w, r, &in) {
		return
	}
	if in.ExpiresAt.IsZero() {
		badRequest(w, "expires_at is required", map[string]string{"expires_at": "required"})
		return
	}
	if err := h.s.Findings.Suppress(r.Context(), actorFrom(r.Context()), r.PathValue("id"), in.Reason, in.ExpiresAt); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) unsuppressFinding(w http.ResponseWriter, r *http.Request) {
	if err := h.s.Findings.Unsuppress(r.Context(), actorFrom(r.Context()), r.PathValue("id")); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- runs ----

func (h *handler) listRuns(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	before, limit := q.cursorID(), q.limit()
	if !q.ok(w) {
		return
	}
	page, err := h.s.Runs.List(r.Context(), before, limit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(page.Items, page.NextCursor, toRun))
}

func (h *handler) getRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	run, err := h.s.Runs.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toRun(*run))
}

func (h *handler) diffRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := newQuery(r)
	against := q.int64("against")
	if !q.ok(w) {
		return
	}
	d, err := h.s.Runs.Diff(r.Context(), id, against)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toDiff(d))
}

// ---- jobs ----

func (h *handler) listJobs(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	f := store.JobFilter{Status: model.JobStatus(q.str("status")), TargetID: q.int64("target_id"), BeforeID: q.cursorID(), Limit: q.limit()}
	if !oneOf(string(f.Status), "queued", "running", "succeeded", "failed", "canceled") {
		q.fields["status"] = "unknown job status"
	}
	if !q.ok(w) {
		return
	}
	page, err := h.s.Jobs.List(r.Context(), f)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(page.Items, page.NextCursor, toJob))
}

func (h *handler) triggerJob(w http.ResponseWriter, r *http.Request) {
	var in jobRequestDTO
	if !decode(w, r, &in) {
		return
	}
	j, created, err := h.s.Jobs.Trigger(r.Context(), actorFrom(r.Context()), service.JobRequest{
		TargetID: in.TargetID, Repo: in.Repo, RepoURL: strings.TrimSpace(in.RepoURL), Branch: in.Branch,
		AuthProfile: in.AuthProfile, Force: in.Force, Trigger: model.TriggerManual,
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, toJob(*j))
}

func (h *handler) getJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	j, err := h.s.Jobs.Get(r.Context(), id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toJob(*j))
}

func (h *handler) cancelJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := h.s.Jobs.Cancel(r.Context(), actorFrom(r.Context()), id); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// ---- system ----

func (h *handler) listSources(w http.ResponseWriter, r *http.Request) {
	ss, err := h.s.System.Sources(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(ss, "", toSourceStatus))
}

func (h *handler) listNotifiers(w http.ResponseWriter, r *http.Request) {
	ns, err := h.s.System.Notifiers(r.Context())
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(ns, "", toNotifier))
}

func (h *handler) testNotifier(w http.ResponseWriter, r *http.Request) {
	if err := h.s.System.TestNotifier(r.Context(), actorFrom(r.Context()), r.PathValue("name")); err != nil {
		h.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) listAudit(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r)
	before, limit := q.cursorID(), q.limit()
	if !q.ok(w) {
		return
	}
	page, err := h.s.System.Audit(r.Context(), before, limit)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list(page.Items, page.NextCursor, toAudit))
}
