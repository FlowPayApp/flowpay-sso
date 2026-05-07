# Integración FlowPay SSO ↔ FlowPay Backend

## Objetivo

`flowpay-sso` **autentica** al usuario y emite credenciales. `flowpay-backend` **autoriza** cada request usando esa credencial y obtiene el `company_id` (tenant) sin confiar en query params arbitrarios.

## Flujo recomendado

1. El usuario inicia sesión contra **flowpay-sso** (formulario, OAuth, etc.).
2. **flowpay-sso** devuelve un **access token** (JWT recomendado).
3. El frontend envía `Authorization: Bearer <token>` a **flowpay-backend**.
4. **flowpay-backend** valida la firma del JWT (clave pública / JWKS del SSO) y extrae claims, p. ej.:
   - `sub`: id de usuario
   - `company_id`: negocio FlowPay (tenant)
   - `email`, `role` (opcional)
5. Los handlers usan solo ese `company_id`; se ignora `?company_id=` en producción o se valida que coincida con el token.

## Claims mínimos (propuesta)

| Claim        | Uso                                      |
|-------------|-------------------------------------------|
| `sub`       | ID estable del usuario                    |
| `company_id`| Tenant en FlowPay (FK a `companies.id`)  |
| `exp` / `iat` | Estándar JWT                          |

Ampliar con `roles` o `permissions` cuando tengas RBAC.

## Red

- Desarrollo: SSO en `localhost:9090`, API en `localhost:8080`, CORS configurado en ambos.
- Producción: HTTPS, cookies `HttpOnly` si usas sesión, o solo Bearer en cabecera.

## Base de datos

Opciones:

- **BD propia** en `flowpay-sso` (tablas `users`, `sessions`, `company_memberships`).
- O **misma instancia PostgreSQL** que FlowPay (mismo `FLOWPAY_SSO_DSN` / `FLOWPAY_DSN` y tablas `users`, `companies`, etc. en `public`) — es el modo actual del MVP.

No dupliques tablas de negocio (`charges`, `clients`) en el SSO.
