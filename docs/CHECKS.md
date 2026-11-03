# LadPock checks

Generated with `ladpock checks --markdown`.


## Secrets

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-DOCKER-002` | Secret baked into the container image | high | all projects |
| `LP-INFRA-004` | Kubernetes Secret committed with its values | high | all projects |
| `LP-SEC-001` | Supabase admin key exposed to the browser | critical | all projects |
| `LP-SEC-002` | Secret exposed through a public environment variable | high | all projects |
| `LP-SEC-003` | Hardcoded credential in the code | critical | all projects |
| `LP-SEC-004` | .env file committed to git | high | all projects |
| `LP-SEC-005` | .env file not covered by .gitignore | medium | all projects |
| `LP-SEC-006` | Credential written into an AI tool config | high | all projects |
| `LP-SEC-007` | Session or app signing key written in the code | high | all projects |
| `LP-TF-005` | Password or key written in infrastructure code | high | all projects |

## Auth and sign-in

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AUTH-001` | Token verification switched off | high | all projects |
| `LP-AUTH-002` | Hardcoded or fallback signing secret | high | all projects |
| `LP-AUTH-003` | Passwords hashed with a fast hash | high | all projects |
| `LP-AUTH-004` | Session token stored in localStorage | low | all projects |
| `LP-AUTH-005` | Cookie security flag turned off | medium | all projects |
| `LP-AUTH-006` | Passwords stored or compared in plain text | high | all projects |
| `LP-AUTH-007` | Login tokens that never expire | low | all projects |
| `LP-AUTH-008` | Password hashing cost set too low | low | all projects |
| `LP-AUTH-009` | Login errors reveal whether an account exists | low | all projects |
| `LP-AUTH-010` | Sign-in or password endpoint has no rate limit | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-AUTH-011` | Token decoded but never verified | high | all projects |
| `LP-INFRA-003` | Database with a default or empty password | medium | all projects |
| `LP-MOB-004` | Login token stored in plain app storage | medium | all projects |
| `LP-SUPA-004` | Supabase getSession() trusted on the server | medium | supabase |

## Authorization

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AUTHZ-001` | Endpoint changes data without checking who is calling | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-AUTHZ-002` | Record fetched by ID without checking it belongs to the user | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-AUTHZ-003` | Authentication only enforced in middleware | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-AUTHZ-004` | Request data saved straight into a database record (mass assignment) | medium | all projects |
| `LP-AUTHZ-005` | Security check written as an assert | low | all projects |
| `LP-AUTHZ-006` | Login requirement switched off for every route | high | all projects |
| `LP-ELEC-004` | Whole IPC channel exposed to the web page | high | electron |
| `LP-MOB-003` | Android component open to other apps | medium | all projects |
| `LP-SUPA-001` | Supabase table without Row Level Security | high | supabase |
| `LP-SUPA-002` | Supabase policy lets everyone through | high | supabase |
| `LP-SUPA-003` | Firebase rules open to everyone | critical | all projects |
| `LP-TAURI-003` | Websites on the internet can call your app's commands | high | tauri |
| `LP-TAURI-004` | Web page can read or write files anywhere | high | tauri |
| `LP-TAURI-005` | Web page can run programs on the computer | high | tauri |
| `LP-TAURI-007` | Asset protocol can serve files from anywhere | medium | tauri |
| `LP-TAURI-009` | Command reads or writes whatever path the page sends | medium | tauri |
| `LP-TF-004` | Access policy grants every permission | high | all projects |

## API abuse and cost

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-ABUSE-001` | Data fetched on every render | medium | all projects |
| `LP-ABUSE-002` | Polling an API more than once every two seconds | medium | all projects |
| `LP-ABUSE-003` | Regular expression built from user input | medium | all projects |
| `LP-ABUSE-004` | Request size limit raised very high | low | all projects |
| `LP-ABUSE-005` | Go HTTP server without timeouts | low | all projects |
| `LP-ABUSE-010` | Paid AI or messaging API reachable without logging in | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-ABUSE-011` | Paid API endpoint has no rate limit | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django |
| `LP-API-002` | GraphQL has no query depth or cost limit | low | all projects |
| `LP-INFRA-005` | Container has no CPU or memory limit | low | all projects |

## Injection

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-ELEC-005` | Link opened in the system without checking the address | medium | electron |
| `LP-ELEC-009` | IPC handler uses page input for files or programs | medium | electron |
| `LP-INJ-001` | HTML injected without sanitising | medium | all projects |
| `LP-INJ-002` | Code or shell command built from input | high | all projects |
| `LP-INJ-003` | SQL query built from strings | high | all projects |
| `LP-INJ-004` | Redirect target taken from the request | medium | all projects |
| `LP-INJ-005` | Server fetches a URL supplied by the user | medium | all projects |
| `LP-INJ-006` | Untrusted data deserialised into objects | high | all projects |
| `LP-INJ-007` | Data rendered as raw HTML in a server template | medium | all projects |
| `LP-INJ-008` | XML parser accepts external entities | medium | all projects |
| `LP-INJ-009` | File path taken from the request | high | all projects |
| `LP-INJ-010` | Database query built straight from the request (NoSQL injection) | high | all projects |
| `LP-INJ-011` | Object properties set from request data (prototype pollution) | medium | all projects |
| `LP-INJ-012` | Template built from user input (server-side template injection) | high | all projects |
| `LP-TAURI-010` | Command runs a program using input from the page | medium | tauri |

## Payments

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-PAY-001` | Webhook accepts requests without checking the signature | high | all projects |
| `LP-PAY-002` | Price or amount taken from the client | high | all projects |

## Crypto and randomness

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-CRYPTO-001` | Predictable random numbers used for a secret value | medium | all projects |
| `LP-CRYPTO-002` | Weak or broken encryption | medium | all projects |

## Config and deployment

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-API-001` | GraphQL introspection or playground left on | low | all projects |
| `LP-CFG-001` | CORS allows any website | medium | all projects |
| `LP-CFG-002` | Source maps published in production | low | all projects |
| `LP-CFG-003` | CSRF protection switched off | medium | all projects |
| `LP-CFG-004` | Django accepts any Host header | medium | django |
| `LP-CFG-005` | Server sends no security headers | low | express, fastify |
| `LP-CFG-006` | Client IP taken from headers anyone can set | low | all projects |
| `LP-CFG-007` | Spring Boot actuator endpoints exposed | high | all projects |
| `LP-CFG-008` | Detailed errors shown to visitors in production | medium | all projects |
| `LP-DOCKER-001` | Container runs as root | medium | all projects |
| `LP-ELEC-001` | Web page inside the app can use Node.js | high | electron |
| `LP-ELEC-002` | Context isolation or the sandbox turned off | high | electron |
| `LP-ELEC-003` | Browser security features turned off in the app | high | electron |
| `LP-ELEC-006` | New windows and navigation aren't restricted | low | electron |
| `LP-ELEC-007` | App window loads a page over plain HTTP | medium | electron |
| `LP-ELEC-008` | No Content Security Policy for the app's pages | medium | electron |
| `LP-INFRA-001` | Container can take over the host | high | all projects |
| `LP-INFRA-002` | Database or admin port open on every network interface | medium | all projects |
| `LP-MOB-001` | App allows unencrypted HTTP traffic | medium | all projects |
| `LP-MOB-002` | Android app is debuggable or allows data backups | high | all projects |
| `LP-MOB-005` | WebView with risky settings | medium | all projects |
| `LP-RUST-001` | App listens for network connections from other machines | low | all projects |
| `LP-TAURI-001` | No Content Security Policy for the app window | high | tauri |
| `LP-TAURI-002` | Content Security Policy lets risky scripts run | medium | tauri |
| `LP-TAURI-006` | Tauri API exposed as a global object | low | tauri |
| `LP-TF-001` | Storage bucket open to the public | high | all projects |
| `LP-TF-002` | Firewall open to the internet on a sensitive port | high | all projects |
| `LP-TF-003` | Database reachable from the internet or stored unencrypted | high | all projects |

## Dependencies and supply chain

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-DEP-001` | Dependency with a known vulnerability | high | all projects |
| `LP-DOCKER-003` | Script downloaded and run in one step | medium | all projects |
| `LP-DOCKER-004` | Base image not pinned | low | all projects |
| `LP-SUP-001` | No lockfile for dependencies | medium | all projects |
| `LP-SUP-002` | GitHub Action not pinned to a commit | medium | github-actions |
| `LP-SUP-003` | Workflow runs pull request code with repository secrets | high | github-actions |
| `LP-SUP-004` | Hidden Unicode characters in code or AI instructions | high | all projects |
| `LP-SUP-005` | Dependency doesn't exist on the package registry | critical | all projects |
| `LP-SUP-006` | Workflow puts untrusted text straight into a script | high | github-actions |
| `LP-SUP-007` | Workflow gives its token write access to everything | medium | github-actions |
| `LP-TAURI-008` | App updates aren't safely verified | high | tauri |

## AI-generated code smells

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-VIBE-001` | TLS certificate checks turned off | high | all projects |
| `LP-VIBE-002` | Security check left as a TODO or bypassed 'for now' | medium | all projects |
| `LP-VIBE-003` | Default or demo password in code | high | all projects |
| `LP-VIBE-004` | Debug mode switched on | medium | all projects |
| `LP-VIBE-005` | Stack trace sent back to the user | medium | all projects |
