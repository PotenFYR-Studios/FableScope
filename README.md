# FableScope

FableScope is a **Rust-first, Tauri v2 desktop pentest platform** designed for authorized security testing across web, API, Active Directory, WiFi, mobile-assisted, red team, and enterprise environments. The project is being built in phases, with **Phase 1 focused on smart recon and fuzzing**.

> **Status:** Active greenfield implementation. **Phase 0 (foundation) and Phase 1 (smart recon & fuzzing) are implemented** as a working Rust/Tauri desktop app with SQLite persistence, a module registry/dashboard, checklist/tool-run engine, reporting (JSON/MD/HTML/CSV/SARIF + CVSS v3.1), and an AI provider abstraction. Phase 1 adds: a mutator-driven fuzz engine, subdomain recon + asset graph, cloud-exposure recon, SimHash dedup/clustering with baseline/novelty triage, result filtering/grouping, a versioned wordlist registry (pin/rollback/integrity), and an offline algorithmic password generator — all covered by workspace unit tests. **Phase 2 is in progress**: hash identification (Hashcat-mode/John-format aware), encoders/decoders, authorization-gated Hashcat/John credential-audit command building + output parsing, and an enterprise HTML report template are implemented and tested; the native web/API crawler and OpenAPI/GraphQL import remain pending. The README distinguishes **implemented** vs **planned/adapter-dependent** modules; external/hardware/cloud/AD/WiFi/mobile/red-team *execution* capabilities (P2–P4) remain gated adapter/planned surfaces, not claimed as fully autonomous offensive coverage. Credential auditing never runs without an explicit per-engagement authorization flag.

---

## Table of Contents

- [Vision](#vision)
- [Core Principles](#core-principles)
- [What FableScope Will Include](#what-fablescope-will-include)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
- [Phase 1: Recon & Fuzzing](#phase-1-recon--fuzzing)
- [Recon, Asset Discovery & Cloud Exposure](#recon-asset-discovery--cloud-exposure)
- [Wordlists, Intel & Auto-Updates](#wordlists-intel--auto-updates)
- [Password Generator & Credential Audit](#password-generator--credential-audit)
- [AI Agents & Integration](#ai-agents--integration)
- [OWASP Checklist-Driven Pentest Engine](#owasp-checklist-driven-pentest-engine)
- [Active Directory Module](#active-directory-module)
- [WiFi Module](#wifi-module)
- [Red Team Module](#red-team-module)
- [Browser Automation](#browser-automation)
- [External Tool Integrations & Tool Manager](#external-tool-integrations--tool-manager)
- [Reporting, Evidence & CVSS Calculator](#reporting-evidence--cvss-calculator)
- [Database & Project Management](#database--project-management)
- [Statistics, Logging, Monitoring & API](#statistics-logging-monitoring--api)
- [Settings, Customization & UI](#settings-customization--ui)
- [UX, Defaults & Background Automation](#ux-defaults--background-automation)
- [Planned Usage](#planned-usage)
- [Security, Legal & Safety](#security-legal--safety)
- [Development Plan](#development-plan)
- [Contributing](#contributing)
- [License](#license)

---

## Vision

FableScope aims to be a high-performance, highly customizable security testing platform that combines:

- **Smart recon and fuzzing** with strong filtering, grouping, deduplication, and triage.
- **Scoped AI agents** - Project and per-module AI agents run inside FableScope, grounded in project data and authorized sources, with user-controlled providers and no forced AI.
- **Rust-native core logic** for performance, safety, and maintainability.
- **Tauri v2 desktop UX** for a modern, realtime, Electron-like app experience without a Node backend.
- **Modular architecture** so web, API, AD, WiFi, mobile, red team, cloud, and external tools can be added without breaking existing workflows.
- **Enterprise-ready operations** including project lifecycle, database options, audit logs, exports, monitoring, and management APIs.
- **Simple, awesome defaults** so users can get value quickly while advanced users can customize every layer.

## Core Principles

| Principle | Description |
|---|---|
| **Rust-only core** | Scanning, fuzzing, AI orchestration, storage, automation, parsing, and business logic are implemented in Rust. |
| **Tauri v2 desktop app** | The desktop shell uses Tauri v2; UI assets run in the system webview, while backend commands/events are Rust. |
| **Authorized use only** | Active scanning, credential auditing, AD/WiFi/red-team workflows, and external tool execution require explicit scope/authorization controls. |
| **Modular by design** | Every capability is a module/submodule with manifests, permissions, jobs, findings, UI routes, and audit policies. |
| **Smart by default** | Baselines, dedup, clustering, adaptive scheduling, AI suggestions, and statistics reduce noise and improve signal. |
| **Observable & auditable** | Jobs, exports, AI egress, config changes, and external tool runs produce structured logs and audit events. |
| **Customizable everywhere** | Profiles, prompts, wordlists, rules, filters, layouts, providers, DBs, integrations, and reports are user-configurable. |
| **Simple by default** | Defaults are sensible, setup is guided, complex configuration runs in the background, and advanced options are progressively disclosed. |
| **AI is optional** | AI is available across modules, but users choose when, where, and which provider/data to use. Non-AI heuristics always remain available. |

---

## What FableScope Will Include

### Module Overview

| Module | Submodules | Planned Capabilities | Status |
|---|---|---|---|
| **Dashboard** | Overview, Jobs, Alerts, Trends | Global stats, active jobs, health, recent findings, wordlist/DB/AI status | Scaffolded |
| **Recon** | Subdomains, Params, Discovery, Fuzzing, Assets | Subdomain/DNS recon, param discovery, URL/JS mining, fuzzing, asset graph, dedup, grouping, triage | Implemented (P1: mutators, subdomain+asset graph, cloud, SimHash dedup/cluster, baseline/novelty, filter/group) |
| **Web** | Crawl, JS, Forms, Vuln Checks | Crawling, JS endpoint extraction, form/auth mapping, web checks, replay | Scaffolded (checklist/tool runs) |
| **API** | REST, GraphQL, OpenAPI, Replay | Spec import, schema-aware fuzzing, auth, replay, response diffing, object/auth testing | Scaffolded (template) |
| **Cloud** | Exposure, IAM, Storage, Config, K8s | Cloud asset discovery, storage/bucket exposure checks, IAM/config posture, Kubernetes/CDN/origin exposure, authorized misconfig validation | Planned (adapter) |
| **AD** | Enum, Hash Audit, Kerberos, NTLM/Auth, Tooling | Authorized AD recon, hash identification/audit, Kerberos/NTLM artifact workflows, tool adapters | Planned (adapter) |
| **WiFi** | Recon, Capture, Audit/Crack, Posture | Authorized wireless recon, capture management, handshake/PMKID audit workflows, reporting | Planned (adapter) |
| **Red Team** | External, Internal, Emulation, C2/Infra, Reporting | Authorized external/internal red team workflows, adversary emulation planning, tooling orchestration, evidence capture | Planned (adapter) |
| **Mobile** | Android, iOS, Import/Reports | External tool integration for mobile pentest workflows, artifact import, normalized findings | Planned (adapter) |
| **Network/Infra** | Discovery, Services, Import | Host/service discovery ingestion, correlation, scope-aware promotion to targets | Planned |
| **Tools** | Password Gen, Encoders, Hash ID, Wordlists | Password generator, encoders/decoders, hash identifier, payload/rule utilities, CVSS calculator | Implemented (algorithmic password gen + CSPRNG/passphrase/mangle/entropy, portable tool mgr, CVSS) |
| **Wordlists** | Sources, Packs, Updates, Versions | SecLists/public/custom wordlists, auto-update, version pinning, rollback, smart packs | Implemented (registry with immutable versions, pin/rollback, integrity, diff; built-in packs + DB packs) |
| **AI Agents** | Project Agent, Module Agents, Providers, Audit | Scoped project/module AI agents, prompt engineering, memory, provider routing, local-only mode, audit trail | Scaffolded (deterministic/no-egress) |
| **Integrations** | Tool Manager, Webhooks, Trackers, Imports | Install/check/connect/validate/run external tools, webhooks, issue trackers, imports/exports | Scaffolded (tool manifests/import/export) |
| **Reports** | Templates, Findings, Evidence, CVSS, Export | Enterprise report templates, CVSS scoring, evidence management, multi-format export, retest tracking | Implemented (JSON/MD/HTML/CSV/SARIF + enterprise HTML exec-summary template, CVSS v3.1, severity/coverage KPIs) |
| **Settings** | Profiles, DB, Security, UI, Keys | Project/workspace settings, DB connections, secrets, themes, keybindings, policies | Scaffolded (config/scope) |

---

## Architecture

### High-Level Stack

| Layer | Technology / Approach |
|---|---|
| **Desktop shell** | Tauri v2 |
| **Core language** | Rust |
| **Async runtime** | Tokio |
| **HTTP/client** | Reqwest/Hyper-based `fs-http` abstraction |
| **Storage** | SQLite default; PostgreSQL/MySQL/other adapters via storage trait |
| **UI** | Tauri webview UI (React or Svelte to be finalized at scaffold time), Rust commands/events/channels |
| **AI** | Provider-agnostic Rust trait layer with local/cloud adapters; optional per feature |
| **Automation** | Job/event bus, background workers, audited external adapters |
| **CLI/API** | Headless CLI and local authenticated management API sharing the same service layer |

### Planned Workspace Layout

```text
FableScope/
  Cargo.toml                         # Rust workspace
  README.md
  apps/
    desktop/                         # Tauri v2 app (Rust commands + UI assets)
  crates/
    fs-core/                         # domain types, traits, errors, scope/authz, events
    fs-config/                       # settings schema, profiles, migrations, secrets refs
    fs-storage/                      # SQLite/Postgres/MySQL adapters, artifacts, search
    fs-bus/                          # jobs, queues, events, cancellation, audit
    fs-http/                         # HTTP client, proxy/TLS, rate limit, retries, fingerprinting
    fs-recon/                        # fuzz engine, mutators, dedup/clustering, scoring
    fs-wordlists/                    # source registry, sync, versions, packs, attribution
    fs-tools/                        # password generator, encoders, hash ID, CVSS, utilities
    fs-ai/                           # providers, routing, prompts, redaction, AI jobs/audit
    fs-ml/                           # local heuristics/ML: simhash, clustering, ranking, anomaly
    fs-browser/                      # browser recorder/replay/automation
    fs-ad/                           # AD models, hash audit orchestration, adapter normalization
    fs-wifi/                         # WiFi models, capture/audit workflows, hardware gating
    fs-redteam/                      # red team planning, emulation workflows, evidence mapping
    fs-reporting/                    # report templates, CVSS, evidence, exports, retest tracking
    fs-adapters/                     # external tool manifests, installers, runners, parsers
    fs-integrations/                 # exports/imports/webhooks/trackers
    fs-api/                          # local management API
    fs-cli/                          # headless CLI
  docs/
  scripts/
```

### Core Execution Pipeline

```text
Target/Asset
  -> Scope & Authorization Guard
  -> Profile/Settings Resolution
  -> Baseline Probe / Context Collection
  -> Scheduler (rate/budget/adaptive)
  -> Mutator / Payload / Wordlist / Tool Selection
  -> Executor (HTTP/Adapter/Tool/Browser)
  -> Normalizer / Fingerprint / Dedup / Cluster
  -> Scoring / Finding Engine / CVSS Mapping
  -> Storage + Event Bus + Audit Log
  -> Realtime UI / Report / Export / API / AI Assist
```

---

## Roadmap

### Phase Roadmap

| Phase | Name | Primary Goal | Key Deliverables | Status |
|---|---|---|---|---|
| **P0** | Foundation | Build the runnable platform skeleton | Tauri v2 app, Rust workspace, config, SQLite, jobs/events/audit, logging, module registry, settings UI | Implemented (realtime push pending) |
| **P1** | Recon & Fuzzing | Deliver smart recon/fuzzing MVP | URL/param/header/body fuzzing, baselines, dedup, filters/grouping, realtime results, wordlists, AI hooks | Implemented (MVP) |
| **P2** | Web/API, Reporting & Credential Audit | Expand core testing and reporting | crawler/API discovery, OpenAPI/GraphQL, reporting engine, CVSS calculator, password generator, hash ID, Hashcat/John adapters | In progress (reporting/CVSS, hash ID, encoders, Hashcat/John adapters done; native crawler + OpenAPI/GraphQL import pending) |
| **P3** | Browser, AD, WiFi, Red Team | Add advanced interactive and specialized modules | browser recorder/replay, AD enum/Kerberos/NTLM adapters, WiFi recon/capture/audit, red team external/internal workflows | Planned |
| **P4** | Enterprise & Red Team Platform | Scale to full enterprise use | RBAC-ready model, distributed jobs, advanced reporting, cloud/network/OSINT, plugin SDK, SIEM/integrations, retest/compliance workflows | Planned |

### Milestone Checklist

- [x] P0: Cargo workspace + Tauri v2 desktop shell (initial)
- [x] P0: Config/profiles schema + JSON import/export/validation (initial)
- [x] P0: SQLite storage + migrations + audit log (initial)
- [~] P0: Job/event bus + realtime UI channel (jobs/audit stored; realtime push stream still pending)
- [x] P1: Fuzz engine + mutators + payload sources (`fs-recon::mutators`: wordlist/numeric/boundary/boolean/type-juggle/case/encoding/path-traversal/affix families with dedup + provenance; `generate_smart_fuzz_targets` + `smart_fuzz` command)
- [x] P1: Subdomain/DNS/URL/param recon + asset graph (`fs-recon::subdomain`: brute + permutation candidate generation, scope guard, `AssetGraph`; `subdomain_scan` command resolves via scoped probe)
- [x] P1: Cloud exposure recon (storage/CDN/origin/mapping) with scope guard (`fs-recon::cloud`: S3/GCS/Azure/Spaces read-only candidates + exposure indicators; `cloud_scan` command promotes high-signal findings)
- [x] P1: Baseline/dedup/clustering/filter/grouping (`fs-recon::fingerprint` SimHash dedup + clustering + soft-404 baseline/novelty scoring; `fs-recon::filter` predicates + grouping; `triage_recon`/`query_recon` commands)
- [x] P1: Wordlist registry + SecLists integration + version pinning (`fs-wordlists::registry`: content-addressed immutable versions, pin/rollback, integrity verify, diff, built-in SecLists/Assetnote/PayloadsAllTheThings/FuzzDB sources)
- [x] P1: AI provider abstraction/config profiles (schema present; runtime routing pending)
- [x] P1: Password generator (algorithmic mode first) (`fs-tools::password`: CSPRNG policy generation, Diceware passphrases, mangling rules, entropy estimation, dedup; `generate_passwords`/`generate_passphrase`/`mangle_word` commands)
- [~] P2: OWASP checklist engine + coverage matrix + evidence/validation model (templates, checklist status, evidence refs, run linkage, confirmed export started)
- [x] P2: Reporting engine + CVSS calculator + enterprise templates (`fs-reporting`: CVSS v3.1 calculator, severity breakdown, checklist-coverage KPI, `render_enterprise_html` exec-summary report; `export_project_report format=enterprise`)
- [x] P2: Hashcat/John adapters + hash audit workflows (`fs-tools::hashid` ranked identification w/ Hashcat mode + John format; `fs-tools::credential_audit` authorization-gated Hashcat/John command building + potfile/`--show` parsing; `fs-tools::codec` encoders; `build_credential_audit`/`identify_hash`/`codec_transform` commands, Hashcat/John registered in the gated tool manager)
- [~] P2: Web/API crawler + OpenAPI/GraphQL discovery + response diffing (checklist/tool-run flow present; native crawler + spec import pending)
- [ ] P3: Web/API/Mobile/Cloud OWASP checklist execution + AD/WiFi/browser/red-team adapters
- [ ] P4: Enterprise management, RBAC, distributed execution, advanced reporting/compliance

---

## Phase 1: Recon & Fuzzing

Phase 1 is the first implementation target. It focuses on making recon/fuzzing **smart, fast, low-noise, and highly customizable**.

### P1 Capabilities

| Area | Planned Functionality |
|---|---|
| **Targets** | URLs, hosts, endpoints, parameterized templates, imported endpoint lists, scoped API targets, subdomains, cloud-mapped assets. |
| **Subdomain & DNS recon** | Passive/active subdomain enumeration, DNS record mapping, wildcard detection, resolver consensus, vhost probing, takeover-candidate validation. |
| **URL/endpoint recon** | Crawl, sitemap/robots, JS endpoint mining, historical/imported URLs, OpenAPI/GraphQL discovery, endpoint normalization. |
| **Parameter recon** | Query/body/header/cookie/path/GraphQL parameter discovery from wordlists, JS, specs, traffic/imports, reflection and behavior analysis. |
| **Fuzz surfaces** | Path/directory/file/extension, query parameter name/value, headers, cookies, JSON/form/multipart body fields, method/method override, content-type/encoding variants. |
| **Smart fuzzing** | Baseline calibration, adaptive payload prioritization, feedback-driven scheduling, mutation strategies, noise suppression, similarity clustering. |
| **Mutators** | Wordlist, numeric/range, boolean, type juggling, boundary values, encoding/decoding chains, case/path normalization, prefix/suffix, template-aware mutations, JSON shape mutation. |
| **Cloud exposure recon** | Storage bucket/blob discovery, CDN/origin mapping, cloud asset fingerprinting, public exposure indicators, authorized misconfig validation/import. |
| **Dedup/noise reduction** | Normalized response fingerprints, SimHash/MinHash/LSH-like clustering, baseline-delta scoring, anomaly scoring. |
| **Rate & safety controls** | Per-host/global concurrency, RPS limits, jitter, 429/5xx backoff, retries, timeouts, stop conditions, scope allowlist enforcement. |
| **Realtime results** | Live event stream, virtualized result table, request/response inspector, diff against baseline, progress/stats strip. |
| **Triage** | Tag, confirm, mark false positive, notes, bulk actions, replay, export selected. |

### Filters & Grouping

FableScope will support deep filtering and grouping to handle large enterprise scans.

| Filter/Group Dimension | Examples |
|---|---|
| **Response** | Status/class, content length, words/lines, response time, content-type, redirect target, headers, regex contains/not contains |
| **Fingerprint** | Baseline delta, similarity cluster, anomaly score, novelty score, error/TLS type |
| **Fuzz metadata** | Payload, mutator, payload family, wordlist/source, fuzz location, parameter name, endpoint |
| **Triage** | Tag, confidence, severity, confirmed/false positive, AI label, notes present |
| **Grouping** | Endpoint, parameter, status, cluster, host, technology, payload family, finding type, wordlist source |

### Smart Scan Flow (Planned)

1. Create/select project and scope policy.
2. Add targets and choose fuzz profile (quick, balanced, deep, custom).
3. Select wordlists/payload packs or let smart pack builder suggest them.
4. Optionally enable AI assistance for strategy, wordlist expansion, or NL filters.
5. Run baseline probes and calibrate noise thresholds.
6. Execute adaptive fuzzing with realtime streaming results.
7. Triage clusters/findings, replay interesting cases, export evidence.

---

## Recon, Asset Discovery & Cloud Exposure

FableScope's recon engine is designed for **deep, smart, low-noise discovery** across web, API, cloud, network, and mobile-backend surfaces. It combines deterministic enumeration, smart algorithms, ML scoring, and optional scoped LLM agents.

### Recon Coverage Map

| Domain | Capability | Techniques / Sources (Planned) | Output |
|---|---|---|---|
| **Subdomain Recon** | Passive + active subdomain discovery | CT logs, DNS records, search/index sources, zone/permutation, wordlists, vhost probing, certificate SANs, import from amass/subfinder | Validated subdomains, confidence, source, resolution history |
| **DNS/Network Recon** | DNS and host mapping | A/AAAA/CNAME/MX/TXT/NS/SOA, reverse DNS, ASN/CIDR mapping, wildcard detection, takeover candidates, SPF/DMARC metadata | Asset graph, DNS inventory, takeover signals |
| **URL/Endpoint Recon** | Crawl + historical + JS mining | Crawling, sitemap/robots, JS parsing, SourceMap hints, historical URL imports, OpenAPI/GraphQL discovery, Wayback/CommonCrawl-style imports (opt-in) | Endpoint inventory, params, methods, content types |
| **Parameter Recon** | Parameter name/value discovery | URL query, body JSON/form/multipart, headers, cookies, path params, GraphQL args, JS sink/source hints, archived params, response reflection | Parameter catalog, type hints, reflection/injection candidates |
| **Cloud Exposure** | Cloud asset and misconfig discovery | Bucket/blob/storage naming, CDN/origin mapping, cloud host patterns, S3/GCS/Azure storage checks, public snapshot/image/container signals (authorized), IAM/config posture imports | Exposure findings, cloud assets, evidence |
| **Service/API Recon** | Port/service/API fingerprinting | HTTP fingerprinting, API schema detection, GraphQL introspection (authorized), tech stack fingerprints, favicon/hash signatures | Service inventory, tech tags, risk hints |
| **Secrets/Metadata** | Exposure indicators | JS/env/config backup probes, leaked key pattern detection, cloud metadata endpoint checks (authorized/safe), token/header leakage indicators | Sensitive exposure findings with redaction |

### Subdomain Recon (Deep)

| Mode | Planned Capability | Validation / Noise Control |
|---|---|---|
| **Passive** | CT logs, DNS datasets, public intel sources, import from amass/subfinder, cert SAN extraction | Source provenance, dedupe, confidence score, stale-record marking |
| **Active DNS** | Bruteforce, permutation/mutation, recursive discovery, alt-names, zone-aware patterns | Wildcard detection, resolver consensus, TTL-aware caching, retry/backoff |
| **VHost/HTTP** | Host-header probing on resolved IPs, virtual host discovery | Baseline response comparison, content fingerprinting, wildcard vhost filtering |
| **Takeover checks** | CNAME/service takeover candidates | Deterministic fingerprint DB, response validation, no destructive claims without evidence |
| **Scope guard** | Root domain/suffix allowlist, excluded subdomains, rate budget | Hard scope enforcement before active probes |

### Parameter Recon (Deep)

| Surface | Discovery Method | Validation |
|---|---|---|
| **Query params** | Wordlists, JS mining, historical URLs, response reflection, param mining, common framework params | Reflection diff, type/error behavior, baseline comparison |
| **Body params** | JSON/form/multipart schema inference, API spec import, JS client analysis, proxy/imported traffic | Content-type aware mutation, schema validation, duplicate suppression |
| **Headers/Cookies** | Known security/debug headers, app-specific patterns, observed response/request analysis | Safe value probes, canary comparison, auth/session awareness |
| **Path/template params** | Route inference, numeric/UUID/object ID patterns, framework conventions | Object ownership/auth checks, normalization, IDOR-safe validation workflow |
| **GraphQL** | Introspection (authorized), query/mutation/arg discovery, schema diff | Query depth/complexity limits, auth matrix, batching/rate controls |
| **Hidden/debug params** | Feature flags, debug/test/admin params, archived param names | Confirmed only with behavioral evidence; low-FP gating |

### Cloud Exposure & Pentest Recon

| Cloud Area | Planned Checks | Guardrails |
|---|---|---|
| **Storage exposure** | S3/GCS/Azure Blob/container naming, public read/list/write checks, signed URL exposure patterns, backup/object discovery | Authorized targets only; read-only validation by default; no destructive writes |
| **CDN/Origin** | CDN host mapping, origin IP discovery, origin bypass candidates, cache key/header behavior | Evidence-based only; avoid disruptive cache poisoning tests unless explicitly enabled |
| **Cloud assets** | Subdomain-to-cloud mapping, hosted service fingerprints, dangling DNS/takeover candidates | Confidence scoring and provenance |
| **IAM/config posture** | Misconfig imports from Prowler/ScoutSuite/cloud CLI, public IAM/policy exposure indicators, key/secret leak indicators | Adapter-based; normalize findings; redact secrets |
| **Kubernetes/containers** | Exposed dashboards/APIs, container registry exposure, kubeconfig/manifest leak indicators | Authorized scope; safe probes; no exploit payloads by default |
| **Metadata/services** | SSRF-to-metadata validation workflows, cloud metadata patterns, instance identity exposure indicators | Authorized and high-risk gated; OOB/deterministic confirmation only |

### Smart Algorithms & ML for Recon

| Problem | Algorithm / Model | Outcome |
|---|---|---|
| **Noise reduction** | Baseline diff, SimHash/MinHash/LSH, structural clustering | Fewer duplicate/irrelevant results |
| **Prioritization** | Weighted scoring, multi-armed bandit/Thompson sampling | Focus on high-signal targets/params/payloads |
| **Anomaly detection** | MAD/z-score, Isolation Forest-style scoring, timing/size outlier detection | Detect subtle behavioral changes |
| **Parameter relevance** | n-gram/token analysis, TF-IDF, embeddings for semantic grouping (optional local) | Better param name suggestions and grouping |
| **Subdomain prediction** | Permutation models, Markov/n-gram generation, historical naming patterns | Higher-value brute/permutation candidates |
| **Tech fingerprinting** | Signature rules + probabilistic classifier | More accurate stack-aware scan plans |
| **False-positive learning** | Feedback loop from confirmed/FP labels, per-project tuning | Improves precision over time |

### LLM/AI Agent Use in Recon (Optional)

| Agent Task | Input | Output | Control |
|---|---|---|---|
| **Asset understanding** | Scope, DNS, endpoints, tech fingerprints | Recon plan, prioritized targets, missing coverage | User review before active scan |
| **Param discovery assist** | JS, API specs, responses, historical URLs | Candidate param names/locations/types | Schema/behavior validation required |
| **Cloud exposure triage** | Cloud findings, configs, headers, DNS | Exposure explanation, likely impact, remediation draft | Evidence-cited, no auto-confirm |
| **Noise triage** | Clustered anomalies, baseline diffs | Likely FP/interesting labels with confidence | Deterministic checks still required |
| **Natural language recon query** | “show new cloud-exposed subdomains with admin params” | Filter/group preset | Preview before apply |

### Recon Edge Cases & Safety

- Wildcard DNS/vhost responses, CDN caching variance, geo/load-balancer differences.
- Rate limits, WAF blocks, tarpits, soft 404s, transient 5xx/429, DNS poisoning/stale caches.
- JavaScript-heavy apps, SPA routing, GraphQL introspection disabled, undocumented APIs.
- Cloud naming false positives, private storage, signed URLs, provider-specific error formats.
- Strict scope allowlist, passive-first option, conservative defaults, audit logs, and redaction.

`fs-wordlists` will manage public, private, generated, and custom wordlists with version control and provenance.

### Wordlist Sources

| Source | Planned Use | Notes |
|---|---|---|
| **SecLists** | Core discovery, fuzzing, usernames, passwords, payload patterns | Pinned versions, attribution, local cache, category tagging |
| **Assetnote Wordlists** | Fresh subdomain/content discovery lists | Scheduled update checks, opt-in |
| **PayloadsAllTheThings** | Payload patterns and bypass references | Normalized into safe payload/rule metadata |
| **FuzzDB** | Attack patterns and discovery primitives | Tagged by surface/risk/type |
| **fuzz.txt / SamLists / curated sources** | Dangerous file paths, params, filenames, dirs | Deduped and normalized |
| **Custom/internal lists** | Company-specific or engagement-specific terms | Private, scoped, redaction-aware |
| **AI-generated packs** | Context-aware candidates | Opt-in, reviewed/labeled as generated |

### Auto-Update & Version Maintenance

- **Auto-update checks**: manual, daily, weekly, or custom schedule.
- **Immutable versions**: new downloads create versioned cache entries; active packs are never overwritten in-place.
- **Integrity**: SHA-256 hashes, optional signatures when available, source metadata, fetch timestamps.
- **Pin/rollback**: projects can pin wordlist versions; rollback to previous known-good versions.
- **Changelog/diff**: show added/removed/changed entries and pack metadata.
- **Offline mode**: use cached versions when internet is unavailable.
- **Attribution/licensing**: preserve source license/attribution in UI and exports.

### Smart Pack Builder

The smart pack builder will select or build wordlists based on:

- Target type (web, API, AD, WiFi, mobile backend, red team).
- Detected tech stack/fingerprints.
- Engagement scope and naming conventions.
- Historical hit rates and false-positive feedback.
- Optional AI suggestions with provenance labels.

---

## Password Generator & Credential Audit

FableScope will include a global password/credential tooling module, reusable by Recon, AD, WiFi, red team, and reporting workflows.

### Password Generator Modes

| Mode | Description | Default |
|---|---|---|
| **Algorithmic / Offline** | Uses CSPRNG, policy-aware generation, Diceware/passphrases, grammar patterns, mangling rules, Markov/PCFG-style statistical generation from selected authorized wordlists. | Default |
| **AI / Intel-Assisted** | Uses optional authorized context (company/app names, username patterns, domain, locale, season/year, policy rules, known words) and optional scoped public intel to generate/rank candidates. | Opt-in |

### Optional Fine-Tuning Inputs

Users may optionally provide data to improve generation quality:

- Company/product/project names
- Domain and subdomain naming patterns
- Username/email formats
- Password policy (length, charset, complexity, rotation hints)
- Locale/language/season/year context
- Known authorized words or internal terminology
- Existing wordlists/rule sets

### Password Tool Features

- CSPRNG-based generation and entropy estimation.
- Policy-constrained output (length, charset, required classes, exclusions).
- Passphrase/Diceware mode.
- Mangling rules (case, leet, suffix/prefix, year/season, separators).
- Markov/PCFG/statistical candidate generation from selected corpora.
- Duplicate/near-duplicate suppression and max output limits.
- Provenance labels: `algorithmic`, `intel`, `ai`, `hybrid`.
- Export formats: TXT, CSV, JSON.
- Redaction and no-store options for sensitive inputs.

### Credential Audit (Planned)

- Hash identification (NTLM, NetNTLMv1/v2, Kerberos etypes, DCC/DCC2, common hash formats).
- NTLM hash parsing/validation and authorized test-hash generation.
- Hashcat and John the Ripper adapters for authorized password auditing.
- Wordlist/mask/rule/hybrid/combinator job orchestration.
- Resume/checkpoint, potfile/artifact handling, GPU-aware status where available.

---

## AI Agents & Integration

FableScope's AI is designed as **scoped agents inside the tool**, not a generic chatbot. Agents run within the project/application subspace, use only authorized context, and help users operate modules with less friction while keeping full user control.

### Agent Architecture

| Agent Scope | Responsibility | Context Boundary |
|---|---|---|
| **Project AI Agent** | Global project assistant: understands scope, assets, findings, scan history, reports, timelines, and cross-module relationships. | Only the active project/workspace; cannot access other projects unless explicitly selected. |
| **Module/Submodule AI Agent** | Specialized agent per module (Recon, AD, WiFi, Red Team, Reporting, Tool Manager, etc.) with domain prompts, tools, schemas, and guardrails. | Only module-relevant data, artifacts, configs, and approved external intel. |
| **Background Task Agent** | Runs bounded background jobs: triage suggestions, report drafts, wordlist optimization, anomaly summaries, CVSS rationale drafts. | Job-scoped inputs/outputs; writes results as suggestions/artifacts, not silent destructive actions. |
| **User Override** | User can disable AI globally, per project, per module, or per action; can choose provider/model and local-only mode. | User policy always wins over agent behavior. |

### Why Scoped Agents

- **Reduced hallucinations**: agents are grounded in project artifacts, scan results, configs, schemas, and validated tool outputs.
- **Lower noise**: Recon agent sees recon data; AD agent sees AD data; Reporting agent sees findings/evidence. No unnecessary cross-context pollution.
- **Better performance**: smaller, relevant context windows and structured retrieval reduce token usage and latency.
- **Safer actions**: module agents only expose capabilities allowed by that module's permissions, scope, and risk tier.
- **Clear accountability**: every agent response/action is tied to project, module, provider, model, prompt version, and audit ID.

### Agent Engineering (Planned)

| Layer | Design |
|---|---|
| **System prompts** | Versioned, module-specific system prompts with role, allowed tools, forbidden actions, output schema, and safety rules. |
| **Context engineering** | Structured context packs: scope, target metadata, recent findings, selected artifacts, config, tool status, and relevant docs; redacted before egress. |
| **Retrieval (RAG)** | Project-local retrieval over findings, logs, artifacts metadata, report drafts, wordlist metadata, and knowledge base/docs; embeddings optional and local-capable. |
| **Memory** | Project memory (approved facts, preferences, naming conventions, known false positives) and session memory; user can view/edit/delete memory. |
| **Tool calling** | Agents call FableScope internal tools through typed Rust contracts (search findings, get scan stats, propose filter, draft report section, identify hash, check tool status). |
| **Structured outputs** | JSON schemas for filters, findings summaries, CVSS suggestions, report drafts, remediation plans, and workflow plans; validated before UI/action use. |
| **Evaluation** | Prompt/model evals, golden tests, hallucination checks, regression tests, and quality metrics per module agent. |
| **Fresh knowledge** | Optional scoped web/repo intel refresh for latest CVEs, tool versions, wordlists, and techniques; cached with source, timestamp, and confidence. |

### Agent Skills & Knowledge Packs (Internet-Sourced, Curated)

FableScope will import and curate **skills/instructions/playbooks** from across the internet to make agents highly capable, but never blindly trust them. Skills are treated as versioned, reviewed knowledge packs.

| Source Type | Examples (Planned) | Use | Safety Control |
|---|---|---|---|
| **Official standards/docs** | OWASP WSTG/ASVS/MASTG/MASVS, NIST, MITRE ATT&CK, vendor docs | Ground truth for checks, terminology, remediation | Pinned version, citation/provenance, periodic review |
| **Public skill repos** | GitHub security skill packs, pentest playbooks, report templates, agent skill libraries | Reusable agent workflows and prompts | License check, malware/prompt-injection scan, sandboxed import, manual approval |
| **Tool documentation** | Nmap, RustScan, Nuclei, Hashcat, Burp, cloud CLIs, AD/WiFi tools | Accurate tool usage, flags, parsing, troubleshooting | Version-pinned docs, adapter capability mapping |
| **Bug bounty methodology** | Public writeups, disclosed reports, program rules/policies, recon methodologies | Improve prioritization, edge-case coverage, reporting quality | Scope-aware filtering, no unauthorized technique execution, source confidence scoring |
| **Internal FableScope learnings** | Confirmed findings, FPs, retests, operator feedback | Improve precision and reduce repeated mistakes | Per-project opt-in, redaction, audit, reversible memory |

**Skill lifecycle:** Discover -> Import -> Scan (license/malware/prompt-injection) -> Normalize -> Review/Approve -> Version Pin -> Evaluate -> Enable -> Monitor -> Rollback. Agents cite skill/source IDs in suggestions and reports where applicable.

### Live Intelligence Updates (Checklists, Skills, Wordlists, Intel)

All external intelligence required by the working tool will be kept fresh with a reliable update system.

| Data Type | Update Triggers | Default Cadence | Safety / Reliability |
|---|---|---|---|
| **OWASP checklists/mappings** | Startup, periodic, manual, source change detected | Startup check + every 6h (configurable) | Version pin, diff/changelog, rollback, provenance |
| **Agent skills/knowledge packs** | Startup, periodic, manual, repo release/watch | Startup check + every 1h (configurable) | Malware/prompt-injection scan, license check, approval gate, rollback |
| **Wordlists** | Startup, periodic, manual, source release/commit | Startup check + every 1h (configurable, aggressive: 15m) | SHA-256/signature, immutable versions, pin/rollback, attribution |
| **Tool/intel feeds** | Startup, periodic, manual | Startup check + every 30m-6h by feed type | Source confidence, cache TTL, stale-data warnings, offline fallback |
| **CVE/advisory metadata** | Startup, periodic, manual | Startup check + every 6h (configurable) | Source provenance, cache, rate limits, last-known-good fallback |

**Update engine behavior:**
- **Startup sync**: quick "check for updates" on app launch; non-blocking background job with visible status.
- **Periodic scheduler**: per-source cadence (minutes/hours), jitter, backoff, ETag/If-Modified-Since/commit-hash checks to avoid unnecessary downloads.
- **Manual control**: "Check now", "Update now", "Pin version", "Rollback", "Disable source".
- **Offline/failed updates**: continue with last-known-good cached version; mark source as stale with clear warning.
- **Logging & audit**: every update attempt logs source, trigger, old/new version, hash, size, duration, result, error, and actor (system/user).
- **UI visibility**: update center shows status, last check, next check, changelog, errors, and one-click retry.

### AI Providers

| Provider / Profile | Planned Support | Notes |
|---|---|---|
| **OpenCode** | Planned | Provider/profile integration through OpenCode-compatible configuration and app-managed credentials. |
| **OpenCode Go subscription** | Planned | First-class subscription/profile setup for OpenCode Go users. |
| **Z.AI (standard API)** | Planned | Standard Z.AI API profile, model selection, endpoint/key management. |
| **Z.AI Coding subscription** | Planned | Separate coding subscription/profile preset and endpoint configuration. |
| **OpenAI / OpenAI-compatible** | Planned | Generic OpenAI-compatible adapter for many hosted/local endpoints. |
| **Anthropic** | Planned | Native provider adapter. |
| **Google Gemini** | Planned | Native provider adapter. |
| **Azure OpenAI** | Planned | Deployment/resource-aware configuration. |
| **OpenRouter** | Planned | Aggregated model routing. |
| **Ollama** | Planned | Local/free model support. |
| **LM Studio / llama.cpp / local endpoints** | Planned | Local OpenAI-compatible or native local runtime support. |

### AI Across the Product

| Function | Project Agent | Module Agent | Guardrail |
|---|---|---|---|
| **Recon planning** | Suggests engagement strategy and priorities | Recon agent suggests wordlists, payload families, scan profile | User reviews before active scan |
| **Fuzzing** | Tracks cross-target patterns | Recon agent prioritizes payloads, adapts to feedback, explains anomalies | Budgeted, fallback to heuristics |
| **Triage** | Correlates findings across modules | Module agent labels clusters, summarizes responses/artifacts | Confidence score, human confirmation |
| **Filters** | Saves reusable project views | Module agent converts natural language to filter/group preset | Preview before apply |
| **Password generator** | Applies project naming/policy context | Tools/AD agent generates/ranks policy-constrained candidates | Authorized-use gate, local-only option |
| **AD/WiFi/Red Team assist** | Correlates paths and evidence | Specialized agent suggests workflows, explains artifacts, maps ATT&CK/evidence | Authorized scope, no silent execution |
| **Reports** | Builds cross-module narrative | Reporting agent drafts sections, CVSS rationale, remediation | Evidence-cited, redacted, user review |
| **Settings/Tool Manager** | Recommends project-wide defaults | Tool/Settings agent diagnoses install/validation/config issues | No silent destructive changes |

### AI Controls

- Per-feature, per-project, and per-module agent enable/disable.
- Per-project/provider/model routing and fallback.
- Local-only/no-egress mode.
- Prompt template editor with versioning.
- Structured output schemas (JSON) for automation.
- Token/cost/time budgets and caching.
- Redaction rules before external AI requests.
- AI audit log: provider, model, feature, timestamp, redaction policy, token/cost metadata.
- **User choice first**: AI never silently takes over critical actions; users can run every module with AI off.

---

## OWASP Checklist-Driven Pentest Engine

FableScope's pentest modules will be driven by **explicit OWASP-aligned checklists** plus **adaptive testing intelligence**. Checklists ensure coverage; algorithms, ML, and scoped AI agents improve understanding, prioritization, validation, and false-positive reduction. The tool must not rely on checklists alone.

> **Coverage policy:** A finding is not considered complete until the checklist item has a status, evidence, validation result, and report mapping. "Not applicable" is allowed only with a reason.

### Checklist Sources (Planned)

| Standard / Checklist | Scope | Use in FableScope |
|---|---|---|
| **OWASP Web Security Testing Guide (WSTG)** | Web app pentest | Primary web checklist; mapped to tests, evidence, findings, and report sections. |
| **OWASP Application Security Verification Standard (ASVS)** | Verification requirements | Control/requirement coverage matrix; used for depth and verification confidence. |
| **OWASP Top 10 (Web)** | Risk awareness | Executive mapping and prioritization overlay; not a replacement for WSTG/ASVS. |
| **OWASP API Security Top 10 (2023)** | API risks | API risk taxonomy and reporting mapping. |
| **OWASP API Security Testing Checklist / API testing guidance** | API pentest | Endpoint/object/auth/schema/inventory/rate-limit test coverage. |
| **OWASP Mobile Application Security Testing Guide (MASTG)** | Mobile app tests | Android/iOS test cases, dynamic/static/runtime checks, evidence requirements. |
| **OWASP Mobile Application Security Verification Standard (MASVS)** | Mobile verification | Mobile control coverage and verification level tracking. |
| **OWASP Mobile Top 10** | Mobile risk awareness | Executive/risk mapping overlay. |
| **OWASP ASVS/Top 10 for LLM/Agent features (where applicable)** | AI-assisted features | Safety checks for AI prompts, egress, redaction, and agent tool use. |

### Checklist Execution Model

| Stage | Description | Output |
|---|---|---|
| **Select** | Choose target type (Web/API/Mobile/AD/WiFi/Red Team) and applicable OWASP checklists/profiles. | Checklist plan |
| **Map** | Map each checklist item to FableScope tests, tools, inputs, permissions, and evidence requirements. | Coverage matrix |
| **Plan** | Test planner selects native checks first; escalates to built-in managed tools (Nikto/SQLMap/Nmap/RustScan/etc.) or external adapters only when needed. | Execution plan with risk/cost/coverage |
| **Execute** | Run automated checks, assisted manual workflows, and built-in managed adapters with scoped jobs. | Raw artifacts |
| **Validate** | Confirm with deterministic rules, replay, differential checks, OOB correlation, or manual reviewer confirmation. | Validated finding or FP |
| **Score** | Assign CVSS, confidence, exploitability, asset criticality, and business impact. | Prioritized finding |
| **Report** | Export checklist coverage, findings, evidence, and retest status. | Audit-ready report |

### Built-in Managed Tool Orchestration (Nikto, SQLMap, Nuclei, etc.)

FableScope should be **smart by default**: users shouldn't manually decide when to run Nikto/SQLMap/Nuclei for every case. The checklist/test planner decides based on signals, scope, and risk.

| Tool | When Planner Uses It | Built-in Integration | Guardrails |
|---|---|---|---|
| **Nikto** | Web server misconfig/header/file/cgi/backup checks, OWASP WSTG config-related items, low-confidence native findings needing corroboration | Portable managed bundle: all maintained Nikto templates/profiles mapped to checklist IDs; auto-select profile by target tech/port/scope; templates versioned and updatable | Rate-limited, scope-gated, non-destructive profile defaults, dedupe with native findings |
| **SQLMap** | SQLi candidates from params/forms/API/headers/cookies, checklist validation for injection items, confirmed/potential SQLi only | Portable managed bundle: safe detection first, then controlled confirmation; request/auth/session import from FableScope; result normalization | Explicit high-risk confirmation for intrusive levels, no destructive payloads by default, redacted logs, stop-on-scope/risk breach |
| **Nuclei** | CVE/misconfig/exposure/template checks, fast corroboration, known-tech checks mapped to checklist items | Portable managed bundle: maintained template packs (official/community curated) version-pinned; auto-select by tech/fingerprint/checklist; template IDs in evidence | Safe templates by default, severity/rate limits, template provenance, dedupe, no destructive templates unless explicitly enabled |
| **Nmap/RustScan/Naabu/Masscan** | Network/service discovery, exposure checks, asset inventory, checklist infra items | Portable managed scan profiles and parser pipeline | Scope/rate gating, authorization checks, audited commands |
| **ffuf/httpx/katana/dnsx** | Content discovery, HTTP probing, crawl, DNS resolution | Portable managed profiles mapped to checklist/test cases | Safe defaults, dedupe, evidence normalization |

**Execution principle:** Native Rust checks for speed/coverage -> corroborate with managed portable tools when useful -> validate with deterministic/OOB/manual evidence -> report. All tool runs are logged, version-pinned, reproducible, and mapped to checklist/finding IDs.

### Check Status & Evidence

| Status | Meaning | Required Data |
|---|---|---|
| **Not Started** | Check not executed | Owner, reason/dependency |
| **In Progress** | Running or awaiting manual step | Job ID, logs, progress |
| **Pass** | Control/check passed | Evidence, test method, timestamp |
| **Fail** | Vulnerability/weakness confirmed | Evidence, impact, CVSS, remediation |
| **Potential** | Signal detected but unconfirmed | Raw signal, confidence, validation plan |
| **False Positive** | Signal invalidated | Validation proof, reason, suppression rule |
| **Not Applicable** | Check does not apply | Justification, reviewer, scope context |
| **Blocked** | Cannot test due to access/env constraint | Blocker, required access, workaround |

### No-Miss, Low-False-Positive Strategy

| Control | Implementation |
|---|---|
| **Coverage matrix** | Every OWASP checklist item gets a unique FableScope check ID, mapped to tests, tools, evidence, and report fields. |
| **Checklist gating** | Scans/reports show coverage % and missing checks; release/report can warn or block if critical checks are unreviewed. |
| **Deterministic validation** | Confirm signals with replay, baseline diff, response fingerprinting, schema validation, auth-state comparison, and OOB confirmation where applicable. |
| **Multi-signal confidence** | Combine status, headers, body diff, timing, DOM/render behavior, protocol state, and artifact correlation before marking confirmed. |
| **False-positive controls** | Baseline calibration, dedup clustering, WAF/rate-limit detection, canary checks, error normalization, and manual confirmation workflow. |
| **Edge-case handling** | Redirect loops, soft 404s, CDN/WAF variance, localized content, unstable timing, pagination, rate limits, CSRF tokens, anti-automation, multipart/JSON edge payloads, GraphQL batching, mobile cert pinning, offline mode. |
| **AI-assisted review** | Project/module agents can summarize evidence, suggest likely validation steps, and detect contradictions; AI cannot mark high-impact findings confirmed without deterministic evidence or user approval. |
| **ML/algorithms** | SimHash/MinHash clustering, anomaly scoring, adaptive payload scheduling, ranking models, and feedback from confirmed/FP labels to tune future scans. |
| **Auditability** | Each check stores raw request/response/artifact, normalized result, validator output, reviewer decision, timestamps, and hash/provenance. |

### Bug Bounty Mode (Accuracy-First)

FableScope will include a **Bug Bounty mode** optimized for real-world programs where false positives, scope mistakes, and noisy reports are costly.

| Capability | Planned Detail |
|---|---|
| **Program scope ingestion** | Import program scope from text/CSV/JSON/Burp config: in-scope domains, wildcard rules, apps, APIs, mobile apps, CIDRs, cloud assets, out-of-scope targets, excluded vuln types. |
| **Scope enforcement** | Hard allow/deny rules before active scans. Wildcard handling, subdomain inheritance, URL normalization, port/path constraints, and “ask before out-of-scope” guard. |
| **Rate & impact limits** | Conservative defaults: rate limits, concurrency caps, safe payload profiles, no destructive tests by default, stop-on-anomaly, and program-specific request budgets. |
| **Duplicate/noise reduction** | Fingerprint findings against prior reports/artifacts, dedupe by root cause+asset+endpoint+parameter, cluster similar signals, suppress known FPs. |
| **Evidence-first reporting** | Bug bounty report export with repro steps, impact, affected asset, PoC, request/response, screenshots, CVSS/CWE, remediation, and confidence. |
| **Human-in-the-loop** | High-impact findings require confirmation workflow; AI suggestions are advisory. Manual note/repro editor built in. |
| **Program compliance** | Track program rules: no social engineering, no DoS, no account takeover without permission, testing windows, required headers/user-agent, disclosure constraints. |

### Validation & Testing Strategy (100% Accuracy Target)

> **Note:** No automated security tool can guarantee 100% real-world accuracy in all environments. FableScope's target is **maximum achievable precision**: minimize false positives, avoid false negatives on covered checks, and require evidence-backed confirmation.

| Layer | Method | Purpose |
|---|---|---|
| **Deterministic checks** | Rule-based validators, replay, schema checks, auth-state diff, OOB correlation | High-confidence confirmations |
| **Statistical checks** | Baseline diff, z-score/MAD timing/size analysis, canary requests | Reduce noise/WAF/CDN variance |
| **ML models** | Anomaly scoring, clustering, ranking, FP classifier from labeled outcomes | Prioritize real issues, learn from feedback |
| **AI agent review** | Evidence summarization, contradiction detection, missing-step suggestions | Better analyst workflow, not blind confirmation |
| **Test harness** | Golden vulnerable labs, regression corpus, known-FP corpus, fuzzed parsers, benchmark targets | Prevent regressions and measure precision/recall |
| **Confidence gates** | `Confirmed` requires evidence + validator pass; otherwise `Potential`/`Needs Review` | No premature high-severity reporting |

### OOB Validation (SSRF, RCE, XXE, Blind Vulns) - No VPS/Domain Required

For blind/out-of-band vulnerabilities, FableScope will prefer **public OOB services and tools** so users don't need to manage their own VPS/domain. Users can also plug in a self-hosted/internal OOB provider if they want.

| Capability | Planned Detail |
|---|---|
| **Public OOB providers** | Built-in adapters for public services such as **Interactsh** (ProjectDiscovery public servers or self-hosted), **Burp Collaborator** (if user has access), and optional webhook/callback providers. |
| **No-infra mode** | Default "No VPS required" mode generates OOB payloads using selected public provider, polls for callbacks, and stores evidence automatically. |
| **Payload templates** | Safe, authorized payload templates for SSRF, blind RCE command callbacks, XXE/OOB DTD, DNS/HTTP/SMTP pingbacks, blind SQLi OOB, and SSRF-to-cloud-metadata validation workflows. |
| **Correlation IDs** | Every payload gets a unique correlation ID (scan/job/check/finding/target/payload hash) to map callbacks to the exact test case. |
| **Deterministic confirmation** | A callback alone is not enough; FableScope correlates timing, payload ID, target, protocol, request path, and baseline behavior before marking confirmed. |
| **Evidence capture** | Store callback payload, DNS/HTTP request metadata, timestamp, source IP (if provided), provider response, and linked finding/check IDs. |
| **Safety controls** | Authorized scope only, high-risk confirmation for RCE/SSRF active checks, payload allowlists, rate limits, redaction, and disable-by-default destructive payloads. |
| **Provider health & fallback** | Provider availability checks, automatic fallback to another configured public OOB provider, and clear "blocked/no callback" status. |
| **Privacy mode** | Allow local-only/no-external-callback mode; in that mode, blind OOB checks are marked blocked/not-run with reason unless user enables a provider. |

### Web Checklist Coverage (OWASP WSTG/ASVS-Aligned)

| Domain | Checklist Coverage | FableScope Tests (Planned) |
|---|---|---|
| **Information Gathering** | Fingerprinting, metadata, entry points, tech stack, content discovery | Passive/active recon, header/cookie analysis, JS endpoint extraction, content discovery, asset graph |
| **Configuration & Deployment** | HTTP methods, security headers, TLS, platform misconfig, backups, admin interfaces | Header/TLS checks, method tests, backup/file probes, admin exposure checks, environment fingerprinting |
| **Identity Management** | Account provisioning, username enumeration, role/policy consistency | Signup/login/reset enumeration tests, role mapping, account lifecycle checks |
| **Authentication** | Weak passwords, lockout, MFA, session/login bypass, credential recovery | Password policy/audit hooks, lockout/rate-limit tests, auth flow replay, reset flow checks |
| **Authorization** | IDOR/BOLA/BFLA, privilege escalation, path traversal in authz | Object ID mutation, role matrix testing, forced browsing, horizontal/vertical access checks |
| **Session Management** | Cookies, session fixation, timeout, logout, JWT/session tokens | Cookie flags, token entropy/rotation, logout invalidation, fixation/replay tests |
| **Input Validation** | XSS, SQLi, command/template injection, SSRF, XXE, deserialization, path traversal, blind RCE | Payload engine, context-aware probes, public OOB callbacks (Interactsh/Collaborator/webhook adapters, no VPS needed), response diffing, DOM validation |
| **Error Handling** | Verbose errors, stack traces, debug leaks | Error-triggering probes, log/response normalization, sensitive data detection |
| **Cryptography** | Weak TLS/ciphers, insecure storage/transport patterns, token protection | TLS/cipher policy checks, token/cookie/storage inspection, crypto misuse indicators |
| **Business Logic** | Workflow bypass, race conditions, abuse cases, rate limits | Stateful workflow tests, multi-step replay, race harness, rate-limit/abuse checks |
| **Client-Side** | DOM XSS, postMessage, clickjacking, CSP, CORS, WebSockets | Browser-assisted tests, CSP/CORS analysis, frame protection, WS auth/origin checks |
| **Reporting** | Evidence, reproducibility, remediation, retest | Checklist coverage report, PoC artifacts, CVSS, remediation, retest tracking |

### API Checklist Coverage (OWASP API Top 10 + API Testing)

| Domain | Checklist Coverage | FableScope Tests (Planned) |
|---|---|---|
| **Inventory & Exposure** | API inventory, versioning, shadow/deprecated endpoints | OpenAPI/Postman/GraphQL import, endpoint discovery, diff vs documented inventory |
| **Auth & Tokens** | JWT, OAuth flows, token expiry/rotation, weak auth | Token validation, replay, expiry checks, scope/audience/issuer checks, auth matrix |
| **Object/Function AuthZ** | BOLA/IDOR, BFLA, property-level auth | Object ID permutation, role matrix, method switching, hidden field/property tests |
| **Input/Schema** | Injection, mass assignment, schema bypass, type confusion | Schema-aware fuzzing, type/boundary mutation, GraphQL query/mutation fuzzing |
| **Resource Consumption** | Rate limiting, pagination abuse, large payloads, DoS vectors | Throttling tests, pagination/cursor abuse, payload-size controls, safe stress profiles |
| **Config & Transport** | CORS, TLS, headers, verbose errors, debug endpoints | API header/TLS checks, CORS misconfig, error leakage, debug/admin endpoint discovery |
| **Business Logic** | Workflow abuse, race conditions, state transitions | Stateful API sequences, replay, race tests, idempotency and state validation |
| **Data Exposure** | Excessive data, PII/secrets in responses/logs | Response schema diff, sensitive field detection, redaction-aware evidence |

### Mobile Checklist Coverage (OWASP MASTG/MASVS)

| Domain | Checklist Coverage | FableScope Tests (Planned) |
|---|---|---|
| **Mobile Platform** | Permissions, intents/deeplinks, WebView, IPC/exported components | Manifest/entitlement analysis, deeplink tests, exported component checks, WebView config review |
| **Data Storage & Privacy** | Local storage, logs, backups, clipboard, screenshots, PII | Static/dynamic storage checks, filesystem/log/backup inspection, sensitive data detection |
| **Crypto** | Hardcoded keys, weak crypto, insecure RNG, key storage | Static rules, runtime hooks, key storage checks, crypto misuse detection |
| **Auth & Session** | Local auth, biometrics, token handling, session timeout | Auth flow tests, token lifecycle checks, biometric bypass resistance tests in authorized labs |
| **Network** | TLS, cert pinning, hostname validation, cleartext traffic | Proxy/intercept tests, TLS config, pinning behavior, API endpoint validation |
| **Platform Interaction** | IPC, WebView JS bridge, exported services/providers | Bridge/API abuse tests, IPC fuzzing/imports, permission boundary checks |
| **Code Quality/Resilience** | Debug, obfuscation, tamper/root/jailbreak signals, hardcoded secrets | Static analysis, secret scanning, debug build checks, resilience evidence collection |
| **Testing Process** | MASTG test case mapping, MASVS level tracking, evidence | Checklist IDs, evidence artifacts, pass/fail/N/A, retest and report export |

### Checklist-to-Finding Traceability

Every checklist item will map to:

- **FableScope Check ID** and OWASP reference ID (WSTG/ASVS/API/MASTG/MASVS).
- **Test method**: automated, assisted, manual, imported, or external adapter.
- **Evidence**: request/response, screenshot, pcap, log, artifact hash, timestamps.
- **Validation**: deterministic rule, replay, human review, or AI-assisted suggestion.
- **Result**: pass/fail/potential/FP/N/A/blocked with reason.
- **Risk**: CVSS v3.1/v4.0, confidence, exploitability, asset criticality, business impact.
- **Report mapping**: executive summary, technical finding, remediation, retest item.

---

## Active Directory Module

The AD module is planned as an **authorized enterprise assessment** module. It combines native Rust orchestration, parsing, normalization, and reporting with audited external tool adapters.

### AD Submodules

| Submodule | Planned Capabilities | Native / Adapter |
|---|---|---|
| **Enum** | LDAP/AD object enumeration, users/groups/computers/SPNs/delegation/ACL mapping, asset graph, diff over time | Native models + adapters/importers (BloodHound/SharpHound, NetExec, ldapdomaindump, Impacket outputs) |
| **Hash Audit** | Hash identification, NTLM/NetNTLM/Kerberos hash handling, authorized password audit jobs, wordlist/rule/mask orchestration | Native orchestration + Hashcat/John adapters |
| **Kerberos** | AS-REP/Kerberoast/delegation/ticket artifact parsing, risk scoring, timeline correlation | Native parsing + Rubeus/Impacket/Certipy output adapters |
| **NTLM/Auth** | NTLM hash typing, challenge/response parsing, auth surface mapping, relay-path risk modeling (advisory) | Native analysis + Mimikatz/Responder/ntlmrelayx/Inveigh/NetExec artifact adapters |
| **Tooling** | Audited command templates, prerequisite checks, result normalization, workflow builder | Adapter framework |

### AD Hash & Credential Audit

| Feature | Planned Detail |
|---|---|
| **Hash types** | NTLM, LM, NetNTLMv1/v2, DCC/DCC2, Kerberos etypes, common audit formats. |
| **Bruteforce/audit modes** | Wordlist, rules, mask, hybrid, combinator, policy-bound incremental modes via adapter engines. |
| **NTLM** | Identify, parse, validate, redact, and generate test NTLM hashes only for authorized fixtures/lab use. |
| **Rubeus integration** | Adapter/import workflow for authorized Kerberos assessment artifacts on supported Windows environments. |
| **Mimikatz integration** | High-risk, gated adapter/import workflow for authorized credential artifact analysis; no silent execution. |
| **Smart optimization** | AI-suggested masks/rules, policy-aware candidate prioritization, feedback from hit rates, GPU-aware scheduling. |

> **Note:** High-risk AD tooling is gated behind explicit authorization, scope checks, confirmations, audit reasons, and environment capability checks.

---

## WiFi Module

The WiFi module is planned for **authorized wireless security assessments**. Wireless capabilities are hardware/OS/driver dependent; the UI will expose capability matrices and disable unsupported actions with clear reasons.

### WiFi Submodules

| Submodule | Planned Capabilities | Native / Adapter |
|---|---|---|
| **Recon** | SSID/BSSID/channel/encryption/client discovery, signal/timeline, inventory graph, rogue AP heuristics | Native inventory + Kismet/aircrack-ng/tshark/import adapters |
| **Capture** | Monitor-mode preflight, capture session manager, handshake/PMKID artifact detection, pcap indexing | Adapter-heavy (hcxdumptool, airodump-ng, tcpdump/tshark) |
| **Audit/Crack** | Handshake/PMKID extraction workflow, authorized PSK audit jobs, wordlist/rule/mask reuse | Hashcat/John/aircrack-ng/hcxtools adapters |
| **Posture** | WPA2/WPA3/enterprise posture checks, weak config findings, remediation reporting | Native analysis + imports |

### WiFi Edge Cases & Controls

- Hardware capability detection (adapter, monitor mode, injection support, driver).
- OS-specific support matrix (Linux primary for raw capture; limited/import workflows elsewhere).
- Capture quality scoring and artifact validation.
- Large pcap handling via streaming/indexing.
- Strict scope/authorization and audit logging for active wireless actions.

---

## Red Team Module

The Red Team module is planned for **authorized adversary emulation and red team engagements**. It covers both **external** and **internal** perspectives, with strong guardrails, evidence capture, and reporting integration.

### Red Team Perspectives

| Perspective | Focus | Planned Capabilities |
|---|---|---|
| **External** | Internet-facing attack surface and initial access simulation | OSINT/recon ingestion, perimeter mapping, exposed service/API findings, phishing simulation planning artifacts (authorized), external credential/password audit workflows, initial-access evidence tracking, external-to-internal risk narrative |
| **Internal** | Assumed breach / post-access assessment inside authorized environment | AD/endpoint/network enumeration, privilege escalation path analysis, lateral movement evidence mapping, credential exposure workflows, segmentation testing support, impact and detection-gap documentation |
| **Purple/Detection** | Collaboration with defenders | ATT&CK mapping, detection coverage notes, alert/log correlation artifacts, remediation and detection recommendations |

### Red Team Submodules

| Submodule | Planned Capabilities | Implementation |
|---|---|---|
| **Engagement Planner** | Rules of engagement, scope, objectives, assumptions, approval checklist, timeline, operator log | Native |
| **OSINT & Perimeter** | Domain/subdomain/email/asset discovery, exposed service inventory, public intel ingestion | Native + adapters/imports |
| **Initial Access (Authorized)** | Evidence and workflow tracking for authorized initial-access scenarios; payload/artifact handling in controlled labs | Native orchestration + gated adapters |
| **C2 / Infrastructure (Authorized)** | C2/profile/infrastructure metadata tracking, listener/artifact inventory, redirector/opsec checklist, import from approved tools | Native tracking + adapters/imports |
| **Internal Movement** | AD graph paths, lateral movement candidates, credential/artifact correlation, privilege path analysis | Native + AD/network adapters |
| **Adversary Emulation** | ATT&CK technique mapping, emulation plans, test case status, evidence linkage, detection outcomes | Native |
| **Operator Audit & Evidence** | Timestamped operator actions, screenshots/logs/artifacts, command provenance, redaction-aware export | Native |

### Planned Red Team Tooling/Integrations (Authorized, Gated)

| Category | Examples (planned adapters/imports) | Notes |
|---|---|---|
| **Command & Control / Emulation** | Sliver, Mythic, Havoc, Caldera, Atomic Red Team outputs | Metadata/import/orchestration where permitted; no unmanaged silent execution |
| **Internal AD/Network** | BloodHound, NetExec, Impacket, Rubeus, Certipy, Mimikatz artifacts | High-risk gated; audited; normalized findings |
| **Recon/Perimeter** | Nmap, httpx, nuclei, amass, subfinder, naabu, masscan, RustScan | Scope-checked; result normalization |
| **Collaboration/Reporting** | MITRE ATT&CK mapping, evidence packs, retest reports | Native reporting integration |

### Red Team Safety & UX

- **Authorization first**: ROE/scope/approval required before active workflows.
- **High-risk gating**: explicit confirmation, reason, and audit trail for sensitive actions.
- **Background setup**: tool checks, profiles, workspaces, logging, and artifact storage are auto-configured by default.
- **Operator clarity**: plain-language risk labels, preflight checks, and “what will happen” previews.
- **No clutter**: advanced options hidden behind “Advanced” panels; defaults are safe and practical.

---

## Network Scanning & Evidence

FableScope will include a network scanning module that combines **native Rust scanning** (where safe and practical) with **best-in-class external adapters**. The goal is fast discovery, accurate service fingerprinting, and audit-ready evidence.

### Scan Modes

| Mode | Native / Adapter | Planned Capability | Default Use |
|---|---|---|---|
| **Fast TCP discovery** | Native Rust + optional Masscan/Naabu adapter | Async TCP connect/SYN-style discovery where permitted, top ports, custom ranges, rate limits | Quick asset discovery |
| **Full port/service scan** | Nmap adapter | Full port ranges, service/version detection, NSE scripts (approved profiles), OS hints | Deep assessment |
| **Rapid discovery** | RustScan adapter | Fast port finding then optional handoff to Nmap for service details | Speed + depth |
| **UDP/service checks** | Nmap/adapter | Selected UDP services, safe probes, timeout-aware retries | Targeted UDP coverage |
| **Host discovery** | Native + Nmap | ICMP/TCP/ARP host discovery (capability-aware), DNS resolution, live host validation | Scope validation |
| **Import-only** | Native parser | Import Nmap XML/grepable, Masscan JSON, Naabu output, Nessus/OpenVAS where supported | Offline/third-party evidence |

### Tool Integration Strategy

| Tool | Integration | Why | Evidence |
|---|---|---|---|
| **Nmap** | Primary adapter via Tool Manager | Industry-standard service/script scanning and XML output | Raw XML/stdout/stderr, parsed hosts/ports/services, command profile, version, timestamps |
| **RustScan** | Adapter + Nmap handoff | Very fast port discovery; complements Nmap | RustScan output, generated Nmap command, merged findings/assets |
| **Naabu** | Adapter | Lightweight fast port discovery | JSON/output artifact, normalized port inventory |
| **Masscan** | Optional adapter (high-risk/rate-gated) | Large-scale port discovery where authorized | Config, output artifact, scope/rate audit, parsed results |
| **Nikto** | Built-in managed adapter | Web server/misconfig checks mapped to OWASP checklist items; all maintained templates/profiles | Raw output, normalized findings, template/profile ID, request evidence, timestamps |
| **SQLMap** | Built-in managed adapter | Controlled SQLi validation/exploitation assistance for confirmed candidates; mapped to checklist validation | Command/profile, logs, payload/result artifacts, DBMS evidence, redacted outputs |
| **Built-in Rust scanner** | Native `fs-net`/`fs-recon` | No dependency for basic TCP/HTTP discovery; tight UI/log integration | Structured events, probe logs, response metadata, hashes |

### Evidence & Logging for Network Scans

- **Raw artifacts**: original command, stdout/stderr, XML/JSON output files, PCAP (if captured), screenshots/notes.
- **Normalized data**: host, IP, hostname, port, protocol, state, service, version, CPE hints, scripts, confidence.
- **Provenance**: tool name/version, profile, operator, scope, timestamps, source artifact hash.
- **Correlation IDs**: `project_id`, `scan_id`, `job_id`, `check_id`, `asset_id`, `finding_id`.
- **Audit trail**: who ran scan, approval/risk confirmation, rate limits, target scope, and result export hash.
- **Report integration**: network findings map to assets, vulnerabilities, checklist items, CVSS/CWE/CVE where applicable, and annexure evidence tables.

---

## Browser Automation

Planned for Phase 3 as `fs-browser`, with architecture prepared earlier. It provides **browser automation for scripts, sessions, auth flows, and validation** while keeping actions auditable, authorized, and precise.

| Feature | Planned Detail |
|---|---|
| **Engine** | Rust-native CDP automation primary (e.g., chromiumoxide); optional WebDriver adapter (thirtyfour) and Playwright/Puppeteer adapter bridge where useful. |
| **Recorder** | Record login/navigation steps, selectors, assertions, waits, uploads/downloads, and session artifacts. |
| **Replay** | Parameterized replay with deterministic waits, traces, screenshots, DOM snapshots, HAR/network logs, and failure artifacts. |
| **Session reuse** | Capture cookies/storage/tokens/headers as scoped auth profiles for recon/fuzz/web/API workflows; expiry and refresh-aware. |
| **Script runner** | Run recorded flows, scripted actions, and custom automation steps with variable injection, secrets references, and scoped environment. |
| **User-in-the-loop prompts** | When OTP/MFA/CAPTCHA/approval is required, pause safely and ask user via in-app popup/modal; support OTP code, TOTP approval, push confirmation, magic-link confirmation, manual solve, or abort. |
| **Detection & validation** | Detect auth success/failure, MFA challenges, CAPTCHA, bot blocks, rate limits, session expiry, unexpected redirects, DOM changes, and error banners. Validate with assertions, URL/state checks, response indicators, and screenshot/DOM evidence. |
| **Authorized stealth testing** | Opt-in, scope-gated browser profiles, timing controls, proxy/TLS/user-agent configuration, and auditable CDP tuning for authorized detection-resilience testing. |
| **Precision** | Stable selectors, replay logs, assertions, and artifact-backed debugging over brittle automation. |

### OTP/MFA & Human-Input Handling

| Scenario | FableScope Behavior | Evidence |
|---|---|---|
| **OTP/MFA required** | Pause run, show secure popup: "OTP required for <target/account>". User can enter code, confirm push/TOTP done, skip, or abort. | Prompt event, user action (redacted), timestamp, resulting state |
| **CAPTCHA/bot check** | Detect challenge; pause and request user action or switch to approved manual/browser-assisted mode. | Screenshot, DOM indicator, detection rule, outcome |
| **Session expired** | Detect expiry/redirect/login page; optionally re-run login flow or prompt user. | Before/after URL, cookies/state diff, replay log |
| **Unexpected block** | Detect 403/WAF/bot page; stop or backoff per policy; mark blocked with reason. | Response/status, screenshot, headers, audit log |

**Security:** OTP/secrets entered in popups are never logged in plaintext; they are ephemeral by default, optionally stored only in approved secret vault/profile with explicit user consent.

---

## External Tool Integrations & Tool Manager

FableScope will include a **Tool Manager** so users do not need to manually wire complex dependencies. External tools use audited manifests, capability checks, version pins, sandboxed runners, and normalized output parsers.

### Portable-First Tool Manager (No System Install Required)

By default, FableScope uses **portable/integrated tool bundles** so users don't need to install tools system-wide. External/system tools are optional advanced overrides.

| Stage | What FableScope Does | User Experience |
|---|---|---|
| **Provision** | Downloads/verifies portable tool bundle into app-managed tools directory (version-pinned, checksummed). | Automatic on first use/startup; progress and logs visible. |
| **Detect** | Checks bundled version, path, OS/arch, dependencies, permissions, and optional user-provided override. | Clear status: Ready, Updating, Missing, Unsupported, Override. |
| **Connect** | Auto-registers bundled tool path/config/profiles; optional custom path override for advanced users. | Zero-config by default. |
| **Validate** | Runs checksum/signature/version checks, dry-run/health check, template/profile integrity, permission check. | “Validated” badge with remediation actions. |
| **Run** | Executes portable binary/script through audited adapter with scoped working dir, timeout, resource limits, sanitized env. | Simple Run button + presets; advanced flags hidden. |
| **Observe** | Streams stdout/stderr, step timeline, progress, artifacts, exit code, and normalized results. | Realtime logs, step-by-step status, plain-language errors. |
| **Maintain** | Updates bundles/templates periodically/startup/manual; keeps N versions; rollback on failure. | Update center, pin/rollback, changelog, last-known-good. |

### Integration Model

| Component | Purpose |
|---|---|
| **Tool manifest** | ID, source repo, version, checksum/signature, license, OS/arch, deps, capabilities, risk tier, bundled/override mode. |
| **Bundle provisioner** | Downloads/verifies portable bundle into app-managed `tools/` store; supports offline cache and last-known-good. |
| **Template/profile manager** | Maintains Nikto/Nuclei/SQLMap/Nmap profiles/templates, maps them to checklist IDs/test cases, versions and rollbacks. |
| **Runner** | Executes with scoped working dir, timeout, resource limits, sanitized env, audited command preview. |
| **Parser/normalizer** | Converts raw output to FableScope findings/assets/artifacts with provenance. |
| **Health monitor** | Tracks bundle health, last validation, version drift, template freshness, and compatibility. |

### Planned External Integrations

| Domain | Tools / Integrations (planned) | Mode |
|---|---|---|
| **AD** | Rubeus, Mimikatz, BloodHound/SharpHound, Impacket, NetExec/CrackMapExec, Certipy, BloodyAD, Responder | Portable adapter/import |
| **Credential audit** | Hashcat, John the Ripper | Portable adapter |
| **WiFi** | aircrack-ng suite, hcxdumptool, hcxtools, Kismet, bettercap, tshark/tcpdump | Portable adapter/import (hardware-dependent) |
| **Web/API** | Nikto, SQLMap, Nuclei, ffuf, httpx, katana, dalfox, Burp/ZAP import | Portable managed bundles; checklist-mapped profiles/templates |
| **Network** | Nmap, RustScan, Naabu, Masscan, Nmap XML/JSON imports | Portable adapter/import + native basic TCP/HTTP discovery |
| **OSINT** | amass, subfinder, httpx, dnsx, theHarvester | Portable adapter/import |
| **Mobile** | MobSF, Frida, objection, jadx, apktool, androguard, adb | Portable/adapter/import as supported |
| **Cloud** | Prowler, ScoutSuite, cloud CLIs/APIs | Portable adapter/import where feasible |
| **Red Team / Emulation** | Sliver, Mythic, Havoc, Caldera, Atomic Red Team outputs | Gated adapter/import/orchestration |
| **Collaboration** | Webhooks, Jira, GitHub/GitLab issues, Slack, SIEM exports | Integration/export |

### Tool Manager UX Principles

- **Portable by default**: no system install required for bundled tools; FableScope provisions/validates portable bundles automatically.
- **One-click where safe**: provision, validate, run, update, and rollback from the UI.
- **No hidden magic**: every step is logged and visible in a timeline (command, profile/template, version, artifacts, exit code).
- **Smart defaults**: recommended bundle version, checklist-mapped profile/template, safe resource limits, auto-configured paths.
- **Reviewable runs**: "What happened" view shows selected templates/profiles, inputs, outputs, parsed findings, and raw artifacts.
- **Plain-language errors**: “Missing NVIDIA driver” or “Bundle validation failed” with fix actions.
- **Advanced optional**: raw command args, env overrides, custom tool paths, and custom manifests are available but not required.

---

## Reporting, Evidence & CVSS Calculator

FableScope will include an enterprise-grade reporting engine designed to produce **Big-MNC-style deliverables** for pentests, red team engagements, vulnerability assessments, retests, and compliance-oriented reviews. Reports are evidence-backed, traceable, customizable, and exportable in all major formats.

### Report Types

| Report Type | Audience | Purpose |
|---|---|---|
| **Executive Summary** | Leadership, non-technical stakeholders | Business risk, key findings, impact, strategic recommendations |
| **Technical Report** | Security engineers, developers, IT/admins | Reproduction, evidence, affected assets, technical remediation |
| **Red Team Report** | Security leadership, blue team, management | Attack narrative, objectives, ATT&CK mapping, detection gaps, lessons learned |
| **Retest Report** | AppSec/engineering/management | Fixed/open/partially fixed findings, regression notes, evidence |
| **Compliance/Mapping Addendum** | GRC/compliance teams | Optional mappings to CWE, OWASP, MITRE ATT&CK, CIS, NIST, ISO 27001, PCI DSS, SOC 2 (as applicable) |
| **Evidence Appendix** | Auditors/technical reviewers | Raw evidence, request/response, screenshots, logs, hashes, timestamps |
| **Checklist Coverage Report** | QA/security reviewers | What was checked, how, outcome, evidence, reviewer, and gaps/N-A reasons |

### Enterprise Report Template (Planned)

| Section | Contents |
|---|---|
| **Cover & Metadata** | Report title, client/org, project, assessment type, dates, version, classification, authors/reviewers/approvers, document ID, revision history |
| **Document Control** | Version history, change log, distribution list, confidentiality statement, legal disclaimer, authorization statement |
| **Executive Summary** | Overall posture, critical risks, business impact, key recommendations, trend snapshot, risk heatmap |
| **Scope & Rules of Engagement** | In-scope/out-of-scope assets, authorization, constraints, test windows, assumptions, allowed/forbidden actions |
| **Methodology** | Standards/approach, OWASP checklists used, tools/modules used, manual/automated coverage, AI usage disclosure (if any) |
| **Asset Inventory** | Hosts, endpoints, apps, APIs, cloud assets, AD objects, WiFi assets, external/internal boundaries, ownership/context |
| **Checklist Coverage Summary** | Checklist IDs, coverage %, pass/fail/potential/FP/N-A/blocked counts, untested items, reviewer notes |
| **Attack Narrative / Timeline** | Chronological activity, major paths, key decision points, ATT&CK mapping for red team |
| **Findings Summary** | Severity distribution, heatmap, top risks, quick wins, strategic fixes, affected asset table |
| **Detailed Findings** | Full finding record (see schema below), PoC, evidence, remediation, retest state |
| **Risk & Prioritization** | CVSS + business context + exploitability + asset criticality + exposure + compensating controls |
| **Remediation Roadmap** | Immediate/short-term/long-term fixes, effort estimate, owner suggestions, verification steps, dependencies |
| **Retest Results** | Status by finding, retest evidence, residual risk, closure notes, reopened findings |
| **Compliance Mapping** | OWASP/CWE/CVE/ATT&CK/NIST/CIS/ISO/PCI/SOC2 mappings where applicable, coverage gaps, disclaimers |
| **Appendix & Annexures** | Evidence, logs, tool output, wordlists used, scan config, checklist export, hash/artifact inventory, glossary, raw data tables |

### Detailed Finding Schema (Per Vulnerability)

Each finding/report record is designed to be complete, auditable, and exportable.

| Field | Description |
|---|---|
| **Finding ID** | Unique immutable ID (e.g., `FS-WEB-2026-000123`) with project/module prefix. |
| **Name / Title** | Clear vulnerability/finding name. |
| **Category** | Domain/category (Web, API, Mobile, Cloud, AD, WiFi, Red Team, Network, Config). |
| **Subcategory / Type** | Specific issue type (IDOR, SQLi, SSRF, misconfig, weak password policy, etc.). |
| **OWASP Mapping** | WSTG/ASVS/API Top 10/MASTG/MASVS/Top 10 references. |
| **CWE** | CWE ID(s) and names. |
| **CVE** | Related CVE(s) where applicable; N/A if not CVE-based. |
| **CVE Score / Vector** | CVE/NVD score and vector if available; source-linked. |
| **CVSS** | FableScope-assessed CVSS v3.1/v4.0 score, severity, and vector string. |
| **Severity** | Informational/Low/Medium/High/Critical (and internal scoring rationale). |
| **Impact Severity** | Business/technical impact severity, considering asset criticality and exposure. |
| **Likelihood / Exploitability** | Ease of exploitation, prerequisites, attacker position, automation potential. |
| **Risk Score** | Combined risk rating (CVSS + context) with transparent formula. |
| **Confidence** | Confirmed/High/Medium/Low with validation evidence. |
| **Status** | Draft, Triaged, Confirmed, Reported, Retest, Fixed, Accepted Risk, False Positive. |
| **Affected Assets** | URLs, APIs, hosts, apps, cloud resources, accounts/roles, components, versions. |
| **Description** | What the issue is, where it exists, and relevant technical context. |
| **Impact** | Technical and business impact; data/systems/users affected; worst-case scenario. |
| **Root Cause** | Missing control, insecure design, misconfiguration, weak validation, etc. |
| **Reproduction Steps** | Deterministic steps to reproduce, prerequisites, and expected/actual behavior. |
| **PoC** | Proof-of-concept details, safe payloads/requests, screenshots, videos, artifacts. |
| **Code Blocks** | Request/response/code/config snippets with syntax highlighting, redaction, and captions. |
| **Evidence** | Linked artifacts with IDs, hashes, timestamps, source tool, and operator/reviewer. |
| **Remediation** | Immediate mitigation, long-term fix, secure design recommendation, verification steps. |
| **References** | Vendor docs, OWASP, CWE/CVE/NVD, advisories, internal tickets, standards. |
| **Sources** | Tool/source that detected it (FableScope module, scanner, manual, import), with provenance. |
| **Owner / Assignee** | Responsible team/person and due date (optional). |
| **Timeline** | First seen, confirmed, reported, retested, closed dates. |
| **Tags / Labels** | Custom labels for filtering, compliance, sprint, or workflow. |

### PoC, Code Blocks & Captions

- **PoC manager**: every finding can include multiple PoCs (HTTP request/response, browser steps, CLI output, screenshots, pcap snippets).
- **Code blocks**: syntax-highlighted blocks for HTTP, JSON, XML, JS, Python, shell, config, headers, and payloads.
- **Caption per block**: each PoC/code block has caption, artifact ID, timestamp, source, redaction state, and relevance note.
- **Redaction controls**: auto-mask secrets/tokens/PII; manual redact before export; original stored only with permission/policy.
- **Evidence integrity**: hash (SHA-256), size, MIME type, capture time, and chain-of-custody metadata.

### Supported Report Formats (Planned)

| Format | Use Case | Notes |
|---|---|---|
| **PDF** | Final client deliverable | Branded, polished, executive-ready, annexures, page numbering, TOC |
| **HTML** | Interactive shareable report | Filterable findings, collapsible evidence, embedded charts/tables |
| **DOCX** | Editable client/internal report | MNC-style template for review and customization |
| **Markdown** | Git/docs/version control | Easy diffing and knowledge base reuse |
| **JSON** | Machine integration | Full structured export for pipelines/APIs |
| **CSV/XLSX** | Tracking and remediation management | Finding register, retest tracker, checklist coverage, asset/finding matrix |
| **SARIF-like / JSONL** | Engineering/security tooling ingestion | Normalized findings for dev workflows where applicable |
| **Evidence bundle (ZIP)** | Audit/archive | Reports + artifacts + hashes + manifest + checklist export |

### Checklist Export & Review (Improvement Loop)

Confirmed checklist results can be exported for review and tool improvement.

| Export | Contents | Use |
|---|---|---|
| **Checklist Coverage Export** | Checklist ID, OWASP ref, status, test method, tool/module, timestamps, reviewer, outcome | Prove what was checked |
| **Check Execution Detail** | Steps run, inputs, config/profile, commands/adapters used, logs, artifacts, validation result | Understand how it was checked |
| **Finding Linkage** | Linked finding IDs, confidence, FP reason, evidence IDs, retest status | Trace outcome to evidence |
| **Improvement Feedback** | False positives, missed detections, edge cases, suggested rule/prompt/model updates | Improve detection and workflow |

Formats: **CSV/XLSX/JSON/JSONL/PDF/HTML**. Exports include document hash, generation time, scope, and optional redaction.

### CVSS Calculator (Built-in)

FableScope will include a built-in CVSS calculator and scoring assistant.

| Capability | Planned Detail |
|---|---|
| **CVSS versions** | CVSS v3.1 and CVSS v4.0 support (versioned scoring engine). |
| **Interactive calculator** | UI sliders/selectors for Base, Temporal/Threat, and Environmental metrics where applicable. |
| **Vector & score** | Real-time score, severity band, and vector string generation. |
| **Per-finding scoring** | Store CVSS score/vector per finding, per asset, and per retest. |
| **CVE/CVSS enrichment** | Optional CVE lookup/import for related CVEs, CVE score/vector/source, with caching and provenance. |
| **Business context overlay** | Optional risk adjustment using asset criticality, exposure, exploit evidence, and compensating controls; CVSS remains preserved. |
| **AI assist (optional)** | Suggest initial metric values from evidence; user reviews and approves final score. |
| **Validation** | Prevent invalid metric combinations; show rationale and scoring history. |
| **Exports** | CVSS/CVE/CWE/risk fields included in PDF/DOCX/HTML/JSON/CSV/XLSX exports. |

### Evidence & Finding Management

- Evidence attachments: screenshots, HTTP exchanges, pcaps, logs, tool output, artifacts, hashes.
- Evidence provenance: source tool, timestamp, operator, scope, hash/integrity.
- Redaction presets for secrets, tokens, PII, credentials, and sensitive payloads.
- Finding lifecycle: Draft -> Triaged -> Confirmed -> Reported -> Retest -> Fixed/Accepted Risk/False Positive.
- Repro steps, impact, remediation, references, CWE/CVE/ATT&CK mapping.
- One-click report generation from selected findings and templates.

### Report Customization & AI-Assisted Generation

| Capability | Description |
|---|---|
| **Template builder** | Create custom report templates, sections, branding, cover pages, headers/footers, and annexures. |
| **Custom fields** | Add organization-specific fields, risk formulas, compliance mappings, and approval workflows. |
| **Custom versions** | Save report versions/snapshots (draft, internal review, client, retest) with diff/history. |
| **AI-assisted drafting (optional)** | Generate executive summaries, finding descriptions, remediation drafts, and language polishing from evidence; user reviews before final. |
| **Multi-language (optional)** | AI-assisted translation/localization with glossary and technical-term preservation; original version retained. |
| **Tone/audience modes** | Executive, technical, developer, compliance, or red-team narrative style. |
| **Quality checks** | Missing evidence/CVSS/repro/remediation warnings, consistency checks, duplicate finding detection, redaction scan before export. |

---

## Database & Project Management

### Database Support

| Database | Planned Role | Notes |
|---|---|---|
| **SQLite** | Default desktop/local DB | WAL, FTS, portable, easy backups, local-first performance |
| **PostgreSQL** | Team/enterprise DB | Concurrency, JSONB, central reporting, strong indexing/search options |
| **MySQL / MariaDB** | Enterprise compatibility | Adapter with capability matrix and conformance tests |
| **Other SQL adapters** | Extensible | Pluggable storage trait with documented capability differences |

### Storage & DB Features

- Storage trait abstraction (`fs-storage`) with adapter conformance tests.
- Connection profiles, TLS, test-connection, credential references.
- Migrations with version tracking and safe checkpoints.
- Backup/restore, integrity manifests, retention policies.
- Vacuum/reindex/analyze/compaction maintenance jobs.
- Artifact/blob storage for large request/response bodies, pcaps, screenshots, logs.
- FTS/search index for findings, assets, logs, and artifacts metadata.

### Project Maintenance

- Workspace > Project > Profile > Scan/Session hierarchy.
- Project templates (web, API, AD, WiFi, red team, enterprise).
- Archive/restore/clone/export/import.
- Scope policies and authorization records per project.
- Project health checks, orphan cleanup, storage usage stats.
- Encrypted export bundles with optional redaction.

---

## Statistics, Logging, Monitoring & API

### Statistics & Dashboards

| Metric Area | Examples |
|---|---|
| **Scan performance** | req/s, queue depth, latency p50/p95, error/429/5xx rates, retries/backoff |
| **Fuzz quality** | hits, unique findings, clusters, baseline deltas, novelty/anomaly scores |
| **Checklist coverage** | checks passed/failed/potential/FP/N-A/blocked, coverage %, unreviewed critical checks |
| **Triage** | confirmed, false positive, untriaged, severity/confidence distribution |
| **AI** | requests, token usage, cost estimate, cache hit rate, provider latency, failures |
| **Wordlists** | source freshness, version, hit rate, pack usage, update status |
| **Tools** | install/validation status, run success/failure, runtime, resource usage |
| **System** | CPU/memory/disk, DB size, artifact size, GPU util/temp (if available) |

### Logging & Monitoring

- Structured `tracing` logs with module/scan/job/request/check/finding correlation IDs.
- Human-readable log view in UI: timeline, step-by-step actions, filter by module/severity/job/check, and raw JSON toggle.
- Redaction filters for secrets, tokens, cookies, hashes, PII, and sensitive inputs.
- Log categories: system, scan, checklist, validation, OOB callback, AI, tool adapter, report/export, audit.
- Rotating file logs and in-app log viewer with search, bookmarks, and export.
- Export logs as JSONL/CSV/HTML timeline; include hash/manifest for audit exports.
- Health checks for DB, providers, wordlist updater, adapters, OOB providers, and job workers.
- Optional Prometheus/OpenTelemetry metrics export.
- Alerts via local notifications/webhooks (planned).

### Management API & CLI

A local authenticated management API will expose the same service layer used by the desktop app and CLI.

| Capability | Planned Endpoint/Use |
|---|---|
| **Jobs** | Start/stop/pause/resume scans, view status, stream events |
| **Stats** | Query metrics, health, queue depth, provider status |
| **Wordlists** | Sync/check/update/pin/rollback sources and packs |
| **Tools** | Detect/install/validate/update/run external tools with audited logs |
| **Reports** | Generate CVSS-scored reports and export bundles |
| **DB maintenance** | Backup, restore, migration status, vacuum/reindex, retention |
| **Integrations** | Trigger webhooks/imports/tool adapter runs with audit |

The API will bind to localhost by default, require token auth, and make remote exposure explicit and opt-in.

---

## Settings, Customization & UI

### Settings & Customization

- Global, workspace, and project profile inheritance.
- **Import/export everything**: settings, profiles, bug bounty programs, scope rules, checklists, wordlist packs, tool profiles, report templates, AI prompts/routes, and workspace bundles as JSON/YAML/ZIP (redaction-aware).
- Editable request templates, headers, cookies, auth profiles, proxy/TLS/client certs.
- Custom wordlists, mutators, payload transforms, rule sets, and filter presets.
- OWASP checklist profiles: WSTG/ASVS/API/MASTG/MASVS selection, check toggles, N/A reasons, evidence requirements, coverage gates.
- Bug bounty profiles: program scope import, in/out-of-scope rules, excluded vuln types, rate/request budgets, safe-mode defaults, disclosure/report templates, custom fields.
- AI provider/model routing, prompt templates, redaction policies, local-only mode.
- DB connection manager and storage retention policies.
- Tool manifests, versions, capability checks, and adapter settings.
- Report templates, branding, CVSS defaults, evidence/redaction rules.
- Theme, density, layout, keybindings, table columns, and reduced-motion settings.

### UI/UX Goals

- **Realtime**: live scan stream, animated counters/sparklines, timeline, no UI freezing on large scans.
- **Clarity**: consistent module/submodule layout, inspector/diff panes, saved views.
- **Performance**: virtualized tables, batched event updates, backpressure-aware rendering.
- **Accessibility**: keyboard-first navigation, focus visibility, high-contrast mode, reduced motion.
- **Customization**: dockable panels, command palette, module layouts, reusable presets.

---

## UX, Defaults & Background Automation

FableScope should feel powerful without being complex. The default experience is designed to “just work” for common authorized testing workflows.

| Principle | Planned Behavior |
|---|---|
| **Awesome defaults** | Balanced scan profile, safe rate limits, SQLite local DB, local logs, auto-save, sensible report template, and recommended wordlists preconfigured. |
| **Background setup** | Wordlist sync, DB migrations, tool detection, health checks, indexing, and cache warming run in background jobs. |
| **Guided setup** | First-run wizard for project, scope, DB, AI provider (optional), and tool checks. |
| **Progressive disclosure** | Simple presets first; advanced knobs available in “Advanced” sections. |
| **Plain-language status** | Clear labels like “Ready”, “Needs install”, “Validation failed”, “Waiting for approval”. |
| **Auto-recovery** | Retry transient failures, resume jobs where possible, and show actionable fix buttons. |
| **No forced AI** | AI features are visible but optional; project/module agents can be disabled per scope, and every AI action has a non-AI path. |
| **Safe confirmations** | Only high-risk actions ask for confirmation; routine actions are smooth and fast. |

---

## Planned Usage

> The commands below are **planned** for the initial implementation. They describe intended usage and may change during scaffolding.

### Prerequisites (Planned)

- Rust stable toolchain (`rustup`)
- Tauri v2 prerequisites for your OS (WebView2 on Windows, system webview deps on Linux/macOS)
- Node.js/pnpm only if the selected UI frontend requires it (Rust backend remains core)
- Optional: Docker/PostgreSQL/MySQL for external DB profiles
- Optional: Ollama/LM Studio for local AI
- Optional external tools: Hashcat, John, Rubeus, Mimikatz, Nmap, aircrack-ng, etc. (can be detected/installed/validated through Tool Manager where supported)

### Install / Run (Planned)

```bash
# Clone
git clone https://github.com/PotenFYR-Studios/FableScope.git
cd FableScope

# Install Rust deps / build workspace
cargo build

# Run desktop app (planned Tauri command)
cargo tauri dev

# Run headless CLI (planned)
cargo run -p fs-cli -- --help
```

### Quick Start Workflow (Planned)

1. **Create a project**: set name, target scope, authorization note, and storage profile.
2. **Use defaults or customize**: default profile works out of the box; advanced settings are optional.
3. **Configure optional AI**: add OpenCode/OpenCode Go/Z.AI/Ollama/etc., or keep AI off.
4. **Check tools**: Tool Manager detects/installs/validates required external tools.
5. **Sync wordlists**: pull SecLists/packs, pin versions, and create a smart pack.
6. **Start a scan/workflow**: recon fuzzing, AD audit, WiFi assessment, or red team workflow.
7. **Monitor live results**: use filters/grouping/clusters, inspector, logs, and stats.
8. **Triage & score**: confirm findings, assign CVSS, map evidence, add remediation.
9. **Export report**: generate executive/technical/red-team report in PDF/DOCX/HTML/JSON/CSV.

### Planned CLI Examples

```bash
# Create a project
fs-cli project create --name "Acme Web" --scope-file ./scope.txt

# Sync wordlists and pin version
fs-cli wordlists sync --source seclists
fs-cli wordlists pin --source seclists --version latest-verified

# Check/install/validate an external tool
fs-cli tools detect hashcat
fs-cli tools install hashcat
fs-cli tools validate hashcat

# Run a URL fuzz scan
fs-cli recon fuzz \
  --project "Acme Web" \
  --target https://example.com/FUZZ \
  --wordlist seclists:Discovery/Web-Content/common.txt \
  --profile balanced \
  --out ./reports/acme-recon.json

# Generate a report with CVSS
fs-cli report generate \
  --project "Acme Web" \
  --template enterprise-technical \
  --format pdf \
  --out ./reports/acme-report.pdf

# Start local management API (localhost only)
fs-cli api serve --bind 127.0.0.1:8787
```

### Planned UI Workflow Examples

| Workflow | Steps |
|---|---|
| **Recon fuzzing** | Project -> Scope -> Target -> Wordlist Pack -> Mutators -> Run -> Live Results -> Group/Filter -> Triage -> Export |
| **Tool install/run** | Integrations -> Tool Manager -> Detect -> Install -> Validate -> Run preset -> View step logs -> Normalized findings |
| **Password generation** | Tools -> Password Generator -> choose offline/AI mode -> optional intel inputs -> policy constraints -> generate -> export |
| **AD hash audit** | AD -> Hash Audit -> import hashes -> identify type -> select Hashcat/John adapter -> choose wordlist/rules/mask -> run audited job -> review findings |
| **WiFi audit** | WiFi -> check adapter capability -> capture/import pcap -> extract handshake/PMKID -> authorized audit job -> report |
| **Red team engagement** | Red Team -> ROE/Scope -> External/Internal plan -> Run gated workflows -> Capture evidence -> ATT&CK mapping -> Report |
| **Reporting** | Reports -> Select template -> Pick findings/evidence -> Calculate CVSS -> Review AI draft (optional) -> Export PDF/DOCX/HTML/JSON |

---

## Security, Legal & Safety

FableScope is intended for **authorized security testing, defensive assessment, research, and education in controlled environments**.

### Mandatory Safety Controls

- **Explicit authorization/scope** required before active scans or high-risk tool runs.
- **Audit logging** for scans, exports, config changes, AI egress, DB maintenance, and external tool execution.
- **Secret redaction** in logs, UI, exports, and AI prompts by default.
- **Local-only AI mode** for sensitive environments.
- **Rate/resource limits** to reduce accidental disruption.
- **High-risk confirmations** for AD credential tooling, WiFi active actions, password auditing, red team actions, and external adapter execution.
- **No hidden telemetry** by default; any external integration/update must be visible and configurable.

### Legal Notice

Only use FableScope against systems, networks, accounts, applications, wireless environments, and data you own or have explicit written permission to test. You are responsible for complying with applicable laws, contracts, and organizational policies.

---

## Development Plan

### Implemented Foundation

- [x] Rust workspace + Tauri v2 desktop shell (`apps/desktop/src-tauri`, UI in `apps/desktop/ui`).
- [x] `fs-core`: domain/checklist/evidence/finding models, scope validation, finding traceability fields.
- [x] `fs-config`: workspace/scan/bug bounty/AI/update config schema, JSON import/export/validation.
- [x] `fs-storage`: SQLite WAL + migrations for projects, scope, jobs, findings, checklist items, tool runs, config snapshots, audit log, recon results; export bundle, confirmed checklist JSON/CSV, timeline.
- [x] `fs-tools`: portable-first manifests, platform bundles, detect/provision/download/SHA256/zip/raw extract, profile/args/correlation/project/check run metadata, artifact capture, manifest import/export.
- [x] `fs-checklists`: OWASP web minimal template, instantiate/coverage, template->check lookup.
- [x] `fs-recon`: scoped HTTP probe, fuzz target generation/dedup.
- [x] Desktop commands/UI: projects, scope save/load, config load/save, checklist load/update/run/export/timeline, recon probe/fuzz/load, tools detect/provision/manifest/run/runs, findings promote/list, audit.
- [x] Added `fs-wordlists` (builtin packs, load/dedup/hash, DB custom packs), `fs-reporting` (simplified CVSS v3.1, JSON/MD/HTML/CSV/SARIF-like report render), `fs-ai` (optional deterministic/no-egress provider from config).
- [x] Desktop commands/UI wired for wordlist packs/save, fuzz by pack, CVSS calc, report export (MD/HTML/CSV/SARIF), confirmed checklist export (JSON/CSV/HTML), AI complete (deterministic/disabled by config), checklist templates seed.
- [x] Checklist promotion links `finding_id` back to checklist item; builtin checklist templates now include web+API minimal.
- [x] Workspace tests green: **24 passed, 0 failed** (`cargo test --workspace --exclude fablescope-desktop`).

### Next Implementation Priorities

1. **P1 fuzz/recon engine** - mutators, baselines, clustering, filters/grouping, DNS/subdomain/asset graph, cloud exposure, realtime event stream.
2. **Wordlists/intel** - SecLists/public registry, auto-update, version pin/rollback, provenance, smart packs.
3. **Checklist/tool execution depth** - vetted OS/arch bundle catalog with checksums/provenance, risk/OOB/auth gates, normalized output->findings/evidence, richer timeline.
4. **AI runtime** - provider adapters, local-only/no-egress enforcement, scoped agents, redaction/audit.
5. **Reporting/safety** - CVSS calculator, evidence-first PDF/HTML/DOCX/JSON/CSV exports, enterprise templates, authorization gates, redaction.

### Quality Targets

- Unit/integration tests for parsers, mutators, dedup, filters, CVSS, and DB adapters.
- Property/fuzz tests for input parsers and mutation engines.
- Benchmark suite for scan throughput, dedup/clustering, and UI event batching.
- Migration/conformance tests for SQLite/Postgres/MySQL adapters.
- Security checks for redaction, scope enforcement, and adapter sandboxing.
- Installer/adapter validation tests with mocked environments and checksum verification.

---

## Contributing

Contributions will be welcome once the initial scaffold is in place.

Planned contribution areas:

- Recon/fuzz engine and mutators
- Wordlist parsers/source adapters
- AI provider adapters and prompt templates
- DB adapters and migrations
- Reporting templates, CVSS engine, and export renderers
- UI/UX components and realtime visualizations
- External tool adapters with safe manifests/installers/parsers
- Docs, tests, benchmarks, and security hardening

When contributing, prioritize:

- Authorized-use safety
- Deterministic/reproducible behavior
- Tests and docs
- Clear provenance for wordlists/tools
- No secrets in logs/tests/fixtures

---

## License

A project license has not been finalized in this repository yet. Add a `LICENSE` file before public release and ensure all bundled wordlists/tools/adapters comply with their upstream licenses and attribution requirements.
