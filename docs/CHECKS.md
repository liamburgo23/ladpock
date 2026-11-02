# LadPock checks

Generated with `ladpock checks --markdown`.


## Secrets

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-SEC-001` | Supabase admin key exposed to the browser | critical | all projects |
| `LP-SEC-002` | Secret exposed through a public environment variable | high | all projects |
| `LP-SEC-003` | Hardcoded credential in the code | critical | all projects |
| `LP-SEC-004` | .env file committed to git | high | all projects |
| `LP-SEC-005` | .env file not covered by .gitignore | medium | all projects |
| `LP-SEC-006` | Credential written into an AI tool config | high | all projects |

## Auth and sign-in

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AUTH-001` | Token verification switched off | high | all projects |
| `LP-AUTH-002` | Hardcoded or fallback signing secret | high | all projects |
| `LP-AUTH-003` | Passwords hashed with a fast hash | high | all projects |
| `LP-AUTH-004` | Session token stored in localStorage | low | all projects |
| `LP-AUTH-005` | Cookie security flag turned off | medium | all projects |
| `LP-AUTH-010` | Sign-in or password endpoint has no rate limit | medium | nextjs |
| `LP-SUPA-004` | Supabase getSession() trusted on the server | medium | supabase |

## Authorization

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AUTHZ-001` | Endpoint changes data without checking who is calling | high | nextjs |
| `LP-AUTHZ-002` | Record fetched by ID without checking it belongs to the user | high | nextjs |
| `LP-AUTHZ-003` | Authentication only enforced in middleware | medium | nextjs |
| `LP-SUPA-001` | Supabase table without Row Level Security | high | supabase |
| `LP-SUPA-002` | Supabase policy lets everyone through | high | supabase |
| `LP-SUPA-003` | Firebase rules open to everyone | critical | all projects |

## API abuse and cost

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-ABUSE-001` | Data fetched on every render | medium | all projects |
| `LP-ABUSE-002` | Polling an API more than once every two seconds | medium | all projects |
| `LP-ABUSE-010` | Paid AI or messaging API reachable without logging in | high | nextjs |
| `LP-ABUSE-011` | Paid API endpoint has no rate limit | medium | nextjs |

## Injection

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-INJ-001` | HTML injected without sanitising | medium | all projects |
| `LP-INJ-002` | Code or shell command built from input | high | all projects |
| `LP-INJ-003` | SQL query built from strings | high | all projects |
| `LP-INJ-004` | Redirect target taken from the request | medium | all projects |
| `LP-INJ-005` | Server fetches a URL supplied by the user | medium | all projects |

## Payments

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-PAY-001` | Webhook accepts requests without checking the signature | high | all projects |
| `LP-PAY-002` | Price or amount taken from the client | high | all projects |

## Crypto and randomness

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-CRYPTO-001` | Predictable random numbers used for a secret value | medium | all projects |

## Config and deployment

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-CFG-001` | CORS allows any website | medium | all projects |
| `LP-CFG-002` | Source maps published in production | low | all projects |

## Dependencies and supply chain

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-DEP-001` | Dependency with a known vulnerability | high | all projects |
| `LP-SUP-001` | No lockfile for dependencies | medium | all projects |
| `LP-SUP-002` | GitHub Action not pinned to a commit | medium | github-actions |
| `LP-SUP-003` | Workflow runs pull request code with repository secrets | high | github-actions |
| `LP-SUP-004` | Hidden Unicode characters in code or AI instructions | high | all projects |
| `LP-SUP-005` | Dependency doesn't exist on the package registry | critical | all projects |

## AI-generated code smells

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-VIBE-001` | TLS certificate checks turned off | high | all projects |
| `LP-VIBE-002` | Security check left as a TODO or bypassed 'for now' | medium | all projects |
| `LP-VIBE-003` | Default or demo password in code | high | all projects |
| `LP-VIBE-004` | Debug mode switched on | medium | all projects |
| `LP-VIBE-005` | Stack trace sent back to the user | medium | all projects |
