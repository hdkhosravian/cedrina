# Permissions & Authorization

Cedrina uses role-based and attribute-based access control (RBAC/ABAC) with Casbin.

- Fine-grained permissions for users, admins, and API clients
- Policy management endpoints for admins
- Enforcement via FastAPI dependencies
- Audit logging for all policy changes

## Key Endpoints
- `GET /api/v1/admin/policies` - List policies
- `POST /api/v1/admin/policies/add` - Add policy
- `POST /api/v1/admin/policies/remove` - Remove policy

## Domain Logic
- See `src/permissions/` for enforcement and policy management
- See `src/domain/services/security/` for logging and error standardization

... (Content to be expanded) ... 