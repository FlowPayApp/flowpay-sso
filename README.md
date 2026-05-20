# FlowPay SSO / Identidad

Servicio **apartado** del API de negocio (`flowpay-backend`). Centraliza autenticación, emisión de tokens y, más adelante, SSO/OIDC con proveedores externos.

## Por qué un repo distinto

- **Límites claros**: cobranza, facturación de uso y reglas de negocio siguen en `flowpay-backend`; identidad, sesiones y políticas de acceso viven aquí.
- **Despliegue y escala independientes**: puedes actualizar login sin tocar el core de FlowPay (y al revés).
- **Menos riesgo de mezclar** middleware de auth con handlers de cobros en un solo binario monolítico gigante.

## Estructura del código

```
flowpay-sso/
├── cmd/server/
├── internal/
│   ├── routes/           → URLs (/auth/*, /api/clients)
│   ├── controller/       → HTTP (auth, clientes)
│   ├── service/          → lógica de clientes
│   ├── repository/       → SQL (tipo DB)
│   ├── config/
│   ├── domain/
│   ├── middleware/
│   └── authjwt/
```

Misma convención que `flowpay-payments` y `flowpay-backend`.

## Qué va aquí (roadmap)

- Registro / login (email, magic link, etc.).
- Emisión y renovación de tokens (p. ej. JWT con `sub`, `company_id`, roles).
- JWKS o clave pública para que **FlowPay-backend** solo **valide** el token (no emite la sesión).
- Integración SSO empresarial (OIDC/SAML) cuando lo necesites.

## Qué no va aquí

- Clientes deudores, cobros, recordatorios, Twilio, adjuntos: eso es **solo** `flowpay-backend`.
- UI del panel de cobranza: `flowpay-frontend` (el front habla con backend y, en login, con este servicio según diseño).

## Contrato con FlowPay-backend

Resumen: el backend de negocio confía en un **JWT firmado por este servicio** (o por tu IdP) y lee `company_id` del payload; no acepta `company_id` arbitrario del cliente sin validar.

Detalle en [`docs/INTEGRACION.md`](docs/INTEGRACION.md).

## Ejecutar (placeholder)

```bash
go run ./cmd/server
```

Por defecto escucha en `:9090`. `GET /health` debe responder `200` y JSON con el estado del servicio.

Variables: ver `.env.example`.

## Próximo paso recomendado

Definir el formato del JWT (claims) y exponer `/.well-known/jwks.json` (o compartir secreto solo en entorno de desarrollo). Luego, middleware en `flowpay-backend` que valide el `Authorization: Bearer` antes de rutas `/api/*`.
