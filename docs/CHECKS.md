# LadPock checks

Generated with `ladpock checks --markdown`.


## Secrets

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AI-001` | AI API key used from the browser | high | all projects |
| `LP-DOCKER-002` | Secret baked into the container image | high | all projects |
| `LP-INFRA-004` | Kubernetes Secret committed with its values | high | all projects |
| `LP-IOT-001` | Wi-Fi password or device login in a sketch | medium | all projects |
| `LP-LIVE-004` | Private file served to anyone | critical | all projects |
| `LP-LOG-001` | Password or token written to the logs | medium | all projects |
| `LP-SEC-001` | Supabase admin key exposed to the browser | critical | all projects |
| `LP-SEC-002` | Secret exposed through a public environment variable | high | all projects |
| `LP-SEC-003` | Hardcoded credential in the code | critical | all projects |
| `LP-SEC-004` | .env file committed to git | high | all projects |
| `LP-SEC-005` | .env file not covered by .gitignore | medium | all projects |
| `LP-SEC-006` | Credential written into an AI tool config | high | all projects |
| `LP-SEC-007` | Session or app signing key written in the code | high | all projects |
| `LP-SEC-008` | All environment variables sent out | critical | all projects |
| `LP-SEC-009` | Build copies every secret into the front end | critical | all projects |
| `LP-SEC-010` | Private key or credentials file in the repository | critical | all projects |
| `LP-SHELL-005` | Password written on a command line | high | all projects |
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
| `LP-AUTH-010` | Sign-in or password endpoint has no rate limit | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-AUTH-011` | Token decoded but never verified | high | all projects |
| `LP-AUTH-012` | Accounts linked by email without proof | medium | all projects |
| `LP-AUTH-013` | Hand-built sign-in link has no state value | medium | all projects |
| `LP-AUTH-014` | Password reset link built from the Host header | medium | all projects |
| `LP-AUTH-015` | Login token set from JavaScript | medium | all projects |
| `LP-INFRA-003` | Database with a default or empty password | medium | all projects |
| `LP-LIVE-005` | Sign-in allows unlimited attempts | medium | all projects |
| `LP-LIVE-010` | Session cookie missing protections | medium | all projects |
| `LP-MOB-004` | Login token stored in plain app storage | medium | all projects |
| `LP-SUPA-004` | Supabase getSession() trusted on the server | medium | supabase |

## Authorization

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AI-009` | MCP server on the network with no login | high | mcp |
| `LP-AUTHZ-001` | Endpoint changes data without checking who is calling | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-AUTHZ-002` | Record fetched by ID without checking it belongs to the user | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-AUTHZ-003` | Authentication only enforced in middleware | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-AUTHZ-004` | Request data saved straight into a database record (mass assignment) | medium | all projects |
| `LP-AUTHZ-005` | Security check written as an assert | low | all projects |
| `LP-AUTHZ-006` | Login requirement switched off for every route | high | all projects |
| `LP-AUTHZ-007` | Private-looking data readable without logging in | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-AUTHZ-008` | Users can choose their own role | high | all projects |
| `LP-AUTHZ-009` | Admin or paid status trusted from the browser | high | all projects |
| `LP-AUTHZ-010` | User ID taken from the request instead of the session | high | all projects |
| `LP-AUTHZ-011` | Login can be switched off with a setting | high | all projects |
| `LP-ELEC-004` | Whole IPC channel exposed to the web page | high | electron |
| `LP-EXT-001` | Extension can read every website | medium | all projects |
| `LP-EXT-002` | Extension settings let websites or remote code in | high | all projects |
| `LP-LIVE-001` | Endpoint answered without logging in | high | all projects |
| `LP-LIVE-008` | One user can read another user's data | critical | all projects |
| `LP-LIVE-009` | Ordinary account reached an admin endpoint | high | all projects |
| `LP-MOB-003` | Android component open to other apps | medium | all projects |
| `LP-SOL-001` | Contract trusts tx.origin | high | all projects |
| `LP-SOL-002` | Contract sends money before updating its records | high | all projects |
| `LP-SOL-003` | Sensitive contract function anyone can call | critical | all projects |
| `LP-SOL-006` | Contract can run code it's handed, or destroy itself | high | all projects |
| `LP-SUPA-001` | Supabase table without Row Level Security | high | supabase |
| `LP-SUPA-002` | Supabase policy lets everyone through | high | supabase |
| `LP-SUPA-003` | Firebase rules open to everyone | critical | all projects |
| `LP-SUPA-005` | Supabase policy lets any signed-in user through | high | supabase |
| `LP-SUPA-006` | Database function runs with admin rights and no fixed search path | medium | supabase |
| `LP-SUPA-007` | Database view skips Row Level Security | medium | supabase |
| `LP-SUPA-008` | Supabase storage open to everyone | high | supabase |
| `LP-SUPA-009` | Firebase rules let any signed-in user through | high | all projects |
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
| `LP-ABUSE-010` | Paid AI or messaging API reachable without logging in | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-ABUSE-011` | Paid API endpoint has no rate limit | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-ABUSE-012` | Anyone can send email or texts to any address | medium | all projects |
| `LP-ABUSE-013` | Endpoint returns a whole table | low | all projects |
| `LP-AI-003` | The caller chooses the AI model or token limit | medium | all projects |
| `LP-AI-006` | AI tool or notebook open to the network | high | all projects |
| `LP-API-002` | GraphQL has no query depth or cost limit | low | all projects |
| `LP-API-003` | Debug, test or seed endpoint left in the app | high | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-API-004` | Scheduled-job endpoint anyone can trigger | medium | nextjs, express, fastify, hono, koa, nestjs, fastapi, flask, django, sveltekit, remix, nuxt, astro, spring, go, rails, laravel, dotnet, trpc, convex, graphql, firebase, supabase, vercel, netlify, cloudflare, aws-lambda, rust-web, elysia, hapi, sinatra, symfony, ktor, jaxrs |
| `LP-INFRA-005` | Container has no CPU or memory limit | low | all projects |
| `LP-UPLOAD-002` | File upload accepts any size or type | medium | all projects |

## Injection

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-AI-002` | AI reply run as code or as a database query | high | all projects |
| `LP-AI-004` | User input written into the AI's system prompt | medium | all projects |
| `LP-AI-005` | AI agent can run code or shell commands | high | all projects |
| `LP-AI-007` | HTML from a user or a model shown without escaping | medium | all projects |
| `LP-AI-008` | MCP tool runs commands or touches files the model chose | high | mcp |
| `LP-ELEC-005` | Link opened in the system without checking the address | medium | electron |
| `LP-ELEC-009` | IPC handler uses page input for files or programs | medium | electron |
| `LP-FLOW-001` | Request data reaches a SQL query | high | all projects |
| `LP-FLOW-002` | Request data reaches a shell command | high | all projects |
| `LP-FLOW-003` | Request data chooses a file path | high | all projects |
| `LP-FLOW-004` | Request data chooses where your server connects | high | all projects |
| `LP-FLOW-005` | Request data chooses where the browser is sent | medium | all projects |
| `LP-FLOW-006` | Request data runs as code | critical | all projects |
| `LP-FLOW-007` | Request data put into a page as HTML | medium | all projects |
| `LP-FLOW-008` | Request data used as a template | high | all projects |
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
| `LP-INJ-013` | Archive unpacked without checking paths inside it | medium | all projects |
| `LP-INJ-014` | Messages accepted from any site | medium | all projects |
| `LP-LIVE-011` | Page puts request input back as raw HTML | high | all projects |
| `LP-LIVE-012` | A stray quote breaks a database query | critical | all projects |
| `LP-LIVE-013` | App redirects to any website | medium | all projects |
| `LP-NATIVE-001` | Function with no bounds check (buffer overflow) | high | all projects |
| `LP-NATIVE-002` | Text printed using a variable as the format | high | all projects |
| `LP-NATIVE-003` | Program runs a shell command it built itself | high | all projects |
| `LP-NATIVE-004` | Temporary file name that can be guessed | medium | all projects |
| `LP-RUST-002` | Shell command built with format! | high | all projects |
| `LP-RUST-003` | SQL query built with format! | high | all projects |
| `LP-SHELL-001` | Script runs text as a command | high | all projects |
| `LP-TAURI-010` | Command runs a program using input from the page | medium | tauri |
| `LP-UPLOAD-001` | Uploaded file saved under the name the user chose | high | all projects |
| `LP-UPLOAD-003` | Uploads saved into a public web folder | medium | all projects |

## Payments

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-PAY-001` | Webhook accepts requests without checking the signature | high | all projects |
| `LP-PAY-002` | Price or amount taken from the client | high | all projects |
| `LP-PAY-003` | Paid status taken from the checkout redirect | high | all projects |

## Crypto and randomness

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-CRYPTO-001` | Predictable random numbers used for a secret value | medium | all projects |
| `LP-CRYPTO-002` | Weak or broken encryption | medium | all projects |
| `LP-CRYPTO-003` | Secret compared in a way that leaks it | low | all projects |
| `LP-SOL-004` | Randomness a miner can predict | medium | all projects |

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
| `LP-CFG-009` | Image optimiser settings are too open | medium | all projects |
| `LP-CFG-010` | Site doesn't insist on HTTPS | medium | all projects |
| `LP-CFG-011` | Database console reachable from the web | high | all projects |
| `LP-DOCKER-001` | Container runs as root | medium | all projects |
| `LP-ELEC-001` | Web page inside the app can use Node.js | high | electron |
| `LP-ELEC-002` | Context isolation or the sandbox turned off | high | electron |
| `LP-ELEC-003` | Browser security features turned off in the app | high | electron |
| `LP-ELEC-006` | New windows and navigation aren't restricted | low | electron |
| `LP-ELEC-007` | App window loads a page over plain HTTP | medium | electron |
| `LP-ELEC-008` | No Content Security Policy for the app's pages | medium | electron |
| `LP-INFRA-001` | Container can take over the host | high | all projects |
| `LP-INFRA-002` | Database or admin port open on every network interface | medium | all projects |
| `LP-INFRA-006` | Web server settings expose files or weak encryption | high | all projects |
| `LP-IOT-002` | Device connects without encryption or checks | medium | all projects |
| `LP-LIVE-002` | Security headers missing from responses | low | all projects |
| `LP-LIVE-003` | App lets any website read its responses (CORS) | medium | all projects |
| `LP-LIVE-006` | Error page shows a stack trace | medium | all projects |
| `LP-LIVE-007` | Server announces its software version | low | all projects |
| `LP-LIVE-014` | Private answer marked as cacheable | medium | all projects |
| `LP-LIVE-015` | Folder contents listed to anyone | medium | all projects |
| `LP-LIVE-016` | API documentation open to anyone | low | all projects |
| `LP-MOB-001` | App allows unencrypted HTTP traffic | medium | all projects |
| `LP-MOB-002` | Android app is debuggable or allows data backups | high | all projects |
| `LP-MOB-005` | WebView with risky settings | medium | all projects |
| `LP-RUST-001` | App listens for network connections from other machines | low | all projects |
| `LP-SHELL-002` | Files made writable by everyone | medium | all projects |
| `LP-SHELL-004` | Script turns off a safety check | medium | all projects |
| `LP-SOL-005` | Old Solidity version with unchecked arithmetic | medium | all projects |
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
| `LP-NATIVE-005` | Program downloaded over plain HTTP | high | all projects |
| `LP-SUP-001` | No lockfile for dependencies | medium | all projects |
| `LP-SUP-002` | GitHub Action not pinned to a commit | medium | github-actions |
| `LP-SUP-003` | Workflow runs pull request code with repository secrets | high | github-actions |
| `LP-SUP-004` | Hidden Unicode characters in code or AI instructions | high | all projects |
| `LP-SUP-005` | Dependency doesn't exist on the package registry | critical | all projects |
| `LP-SUP-006` | Workflow puts untrusted text straight into a script | high | github-actions |
| `LP-SUP-007` | Workflow gives its token write access to everything | medium | github-actions |
| `LP-SUP-008` | Install script downloads or runs code | high | all projects |
| `LP-SUP-009` | Package comes from outside the registry | medium | all projects |
| `LP-SUP-010` | Dependency allows any version | low | all projects |
| `LP-SUP-011` | AI tool runs a package with no fixed version | medium | all projects |
| `LP-SUP-012` | Project runs a command when opened | medium | all projects |
| `LP-SUP-013` | Build script downloads and runs code in one step | medium | all projects |
| `LP-TAURI-008` | App updates aren't safely verified | high | tauri |

## AI-generated code smells

| ID | Check | Default severity | Applies to |
|---|---|---|---|
| `LP-SHELL-003` | Deletes a path that could turn out empty | medium | all projects |
| `LP-VIBE-001` | TLS certificate checks turned off | high | all projects |
| `LP-VIBE-002` | Security check left as a TODO or bypassed 'for now' | medium | all projects |
| `LP-VIBE-003` | Default or demo password in code | high | all projects |
| `LP-VIBE-004` | Debug mode switched on | medium | all projects |
| `LP-VIBE-005` | Stack trace sent back to the user | medium | all projects |
| `LP-VIBE-006` | Type or lint errors ignored in the build | low | all projects |
| `LP-VIBE-007` | Code that wipes the database on start or deploy | high | all projects |
