# ferrumec-perms

Bitset-based, route-level authorization middleware for [Actix Web](https://actix.rs), built for the Ferrumec microservice ecosystem.

Each endpoint (HTTP method + route pattern) is mapped to a single bit in a 128-bit permission bitmap. A user's **grant** (stored in PostgreSQL via `viewset`) holds that bitmap. On every request the middleware looks up the grant, checks the endpoint's bit, and either lets the request through or rejects it.

## Table of contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Permission configuration (JSON)](#permission-configuration-json)
- [The permission bitmap](#the-permission-bitmap)
- [Grants storage](#grants-storage)
- [Granting and revoking permissions](#granting-and-revoking-permissions)
- [Using `Authority` in handlers](#using-authority-in-handlers)
- [HTTP responses](#http-responses)
- [Route matching](#route-matching)
- [Errors](#errors)
- [API reference](#api-reference)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Security notes](#security-notes)

## How it works

```
Request
   │
   ▼
PermissionSet::find(method, path) ──► no match ──► request passes through (no check)
   │ match → bit_id
   ▼
read `permission` cookie  ──► missing ──► 401
   │
   ▼
parse as UUID (grant id)  ──► invalid ──► 500
   │
   ▼
load grant from DB/cache  ──► failure ──► 500
   │
   ▼
insert `Authority` into request extensions
   │
   ▼
role & (1 << bit_id) == 0 ──► 403
   │ else
   ▼
your handler
```

## Installation

This crate is not published to crates.io; add it by path or git:

```toml
[dependencies]
ferrumec-perms = { path = "../permissions" }
# or: ferrumec-perms = { git = "https://github.com/<you>/<repo>" }
```

It depends on `actix-web`, `ferrumec` (features `local`, `pg`), `viewset`, `sqlx` (Postgres), `serde`, `serde_json`, `uuid`, `thiserror`, and `tracing`. Rust edition 2024 is required.

## Quick start

```rust
use actix_web::{web, App, HttpServer, HttpResponse};
use ferrumec_perms::{Permissions, PermissionSet};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // `infra` is anything implementing `ferrumec::Infra`
    // (provides the database pool and cache factory).
    let infra = build_infra().await;

    let permission_set = PermissionSet::from_file("permissions.json")
        .expect("invalid permissions.json");

    HttpServer::new(move || {
        App::new()
            .wrap(Permissions::new(permission_set.clone(), infra.clone()))
            .route("/users", web::get().to(|| async { HttpResponse::Ok().finish() }))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
```

`Permissions::new(permission_set, infra)` builds a `viewset::DefaultRepo<Absolute>` from `infra.database()` and `infra.cache_factory()`, which the middleware uses to load grants.

## Permission configuration (JSON)

```json
{
  "permissions": [
    { "method": "GET",    "url": "/users",           "bit_id": 0 },
    { "method": "POST",   "url": "/users",           "bit_id": 1 },
    { "method": "GET",    "url": "/users/{id}",      "bit_id": 2 },
    { "method": "DELETE", "url": "/users/{id}",      "bit_id": 3 },
    { "method": "GET",    "url": "/files/{tail:.*}", "bit_id": 4 }
  ]
}
```

| Field    | Type   | Description                                              |
|----------|--------|----------------------------------------------------------|
| `method` | string | Any valid HTTP method (`GET`, `POST`, …)                 |
| `url`    | string | An Actix route pattern (see [Route matching](#route-matching)) |
| `bit_id` | number | Bit index, `0..=127`                                     |

Validation (performed by every constructor):

- `bit_id` must be in `0..128`
- `method` must parse as an HTTP method
- the same `(method, url)` pair may not appear twice

Several routes may share one `bit_id`, which lets you create broader permissions such as "manage users".

### Loading

```rust
PermissionSet::from_file("permissions.json")?;      // from a path
PermissionSet::from_reader(std::io::Cursor::new(s))?; // any std::io::Read
PermissionSet::new(vec![/* Permission */])?;          // programmatically
```

`PermissionSet` is immutable once built and shared across workers via `Arc`.

## The permission bitmap

A role is a `u128`. Bit `n` (counted from the right) means "may use endpoints whose `bit_id` is `n`".

| `bit_id` | Mask        | Decimal |
|----------|-------------|---------|
| 0        | `1 << 0`    | 1       |
| 1        | `1 << 1`    | 2       |
| 2        | `1 << 2`    | 4       |
| …        | …           | …       |
| 127      | `1 << 127`  | 2¹²⁷    |

`role = 0b1011` (11) has bits 0, 1 and 3 set, so it can reach endpoints mapped to those bits.

Because many databases have no 128-bit integer type, the role is stored as a **`UUID`** (also 128 bits) and converted with `Uuid::as_u128()` / `Uuid::from_u128()`.

## Grants storage

Grants live in the `grants` table, mapped by the `Absolute` entity:

| Column      | Type | Notes                                           |
|-------------|------|-------------------------------------------------|
| `id`        | UUID | Grant ID. This is the value of the `permission` cookie |
| `user`      | UUID | Owner of the grant (filterable)                 |
| `role`      | UUID | The 128-bit permission bitmap                   |
| `namespace` | UUID | Scope/tenant the grant applies to (filterable)  |

A suggested migration (adjust to your conventions):

```sql
CREATE TABLE grants (
    id        UUID PRIMARY KEY,
    "user"    UUID NOT NULL,
    role      UUID NOT NULL,
    namespace UUID NOT NULL
);
CREATE INDEX grants_user_idx ON grants ("user");
CREATE INDEX grants_namespace_idx ON grants (namespace);
```

Types:

- **`Absolute`**: the full database entity (`id`, `user`, `role`, `namespace`).
- **`Authority`**: the same without `id`; this is what gets placed in request extensions and what `Absolute::create` takes.
- **`UpdateAbsolute`**: update payload; only `role` can change (`user` and `namespace` are immutable).

## Granting and revoking permissions

The `AuthzControls` trait (implemented for both `Absolute` and `Authority`) provides bit-level helpers. Each returns an `UpdateAbsolute` that you pass to the repository's update method:

```rust
use ferrumec_perms::AuthzControls;
use uuid::Uuid;

// Build a permission value with bits 1 and 3 set (0b1010)
let manage_users = Uuid::from_u128((1 << 1) | (1 << 3));

let update = grant.grant(manage_users);  // role | value
let update = grant.deny(manage_users);   // role & !value
let ok     = grant.has(manage_users);    // true only if ALL bits in value are set
```

## Using `Authority` in handlers

When a route matched a permission and the checks pass, the middleware stores the caller's `Authority` in request extensions. `Authority` implements `FromRequest`, so handlers can simply take it:

```rust
use ferrumec_perms::Authority;

async fn whoami(auth: Authority) -> HttpResponse {
    HttpResponse::Ok().json(&auth) // { user, namespace, role }
}
```

Extracting `Authority` on a route where no permission matched (or without the middleware) returns **500 "Configuration Error"**, because nothing populated the extension.

## HTTP responses

| Situation                                              | Status |
|--------------------------------------------------------|--------|
| No permission entry matches the method + path          | Request passes through, no check |
| Matching entry, `permission` cookie absent             | 401    |
| Cookie value is not a valid UUID                       | 500    |
| Grant lookup fails (not found or database/cache error) | 500    |
| Grant's bit for the endpoint is not set                | 403    |
| Grant's bit is set                                     | handler runs |

> **Default-allow:** routes that are *not* listed in the permission set are not protected. List every route you want guarded, or add a catch-all pattern such as `{ "method": "GET", "url": "/{tail:.*}", "bit_id": N }`. Note that `find` returns the *first* match, so put specific entries before catch-alls.

## Route matching

Patterns use Actix's `ResourceDef`, so everything Actix routing supports works:

| Pattern              | Matches                                  |
|----------------------|------------------------------------------|
| `/users`             | exactly `/users`                         |
| `/users/{id}`        | `/users/42`, `/users/abc` (not `/users/`)|
| `/users/{id:\d+}`    | numeric IDs only                         |
| `/files/{tail:.*}`   | `/files/`, `/files/docs/readme.txt`      |

Matching runs against `req.path()` (no query string). Entries are evaluated in insertion order and the first match wins.

## Errors

`PermissionError` is returned when building a `PermissionSet`:

| Variant                              | Cause                                |
|--------------------------------------|--------------------------------------|
| `Io(io::Error)`                      | Permission file couldn't be read     |
| `Json(serde_json::Error)`            | Malformed JSON or missing fields     |
| `InvalidMethod(String)`              | Unparseable HTTP method              |
| `InvalidBitId { bit_id }`            | `bit_id` outside `0..128`            |
| `DuplicatePermission { method, route }` | Same method and route listed twice |

## API reference

Public exports from the crate root:

| Item                | Kind   | Purpose                                              |
|---------------------|--------|------------------------------------------------------|
| `Permissions`       | struct | Actix middleware (`Transform`); wrap your `App` with it |
| `PermissionSet`     | struct | Validated collection of endpoint → bit mappings      |
| `Authority`         | struct | The caller's `user`, `namespace`, `role`; also an Actix extractor |
| `Absolute`          | struct | Database entity for the `grants` table               |
| `AuthzControls`     | trait  | `grant`, `deny`, `has` bit helpers                   |

Key methods:

- `Permissions::new(PermissionSet, impl ferrumec::Infra) -> Permissions`
- `PermissionSet::new(Vec<Permission>)`, `::from_file(&str)`, `::from_reader(R)`
- `PermissionSet::find(&Method, &str) -> Option<&Permission>`

## Project layout

```
src/
├── lib.rs          crate docs and public exports
├── middleware.rs   Permissions transform/service, Authority extractor
├── permission.rs   Permission, PermissionSet, JSON loading, validation
├── repo.rs         Absolute / Authority / UpdateAbsolute, Role, AuthzControls
├── error.rs        PermissionError
└── tests.rs        middleware integration tests
```

## Testing

```bash
cargo test
```

`permission.rs` contains unit tests for matching and validation; `tests.rs` contains Actix integration tests for the middleware.

## Security notes

- The `permission` cookie holds the **grant ID**, which acts as a bearer credential for the grant. Use unguessable UUIDs (v4), and set the cookie `HttpOnly`, `Secure`, and `SameSite` when issuing it.
- Authorization is only as strong as the issuance of that cookie; authenticate users before creating or returning grant IDs.
- Because unlisted routes are allowed through, review your `permissions.json` whenever you add endpoints.
- 128 permission bits are shared across the whole service; plan your `bit_id` allocation (e.g. document it next to `permissions.json`).

## License

Add your license here.
