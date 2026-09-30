# FixBridge full-stack project

Responsive FixBridge web app with an Express API, MongoDB persistence and GridFS file storage. Unlike the earlier browser-only preview, customer, professional and administrator records are stored on the server and shared across browsers connected to the same deployment.

## Run from VS Code

Requirements: Node.js 20 or newer, npm, and a MongoDB database (MongoDB Atlas or local MongoDB).

1. Open this `fixbridge-vscode-project` folder in VS Code.
2. In the VS Code terminal, run `npm install`.
3. Copy `.env.example` to `.env`.
4. In `.env`, set `MONGODB_URI`, `MONGODB_DB`, `ADMIN_EMAIL`, and a strong unique `ADMIN_PASSWORD`. Add `OPENAI_API_KEY` to turn on the AI assistant.
5. Run `npm run dev` in the VS Code terminal.
6. Open `http://localhost:3000` in a browser.

MongoDB Atlas connection setup: create a cluster and database user, copy the Node.js connection URI from the Atlas connect screen, replace its password placeholder, and use that URI as `MONGODB_URI`. Keep `.env` private. Never commit it or place database/API secrets in browser JavaScript.

The administrator account is created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` on the first server start. New customer and professional accounts are created in MongoDB. Professional passwords are hashed with bcrypt; professional photo and resume uploads are stored in GridFS. Professional applications wait for administrator approval before sign-in is allowed.

## Implemented flows

- Sign up and sign in for customers and professionals; administrator account bootstrapped from private environment settings.
- MongoDB-backed user sessions using secure, HttpOnly cookies; account/password records persist across browser sessions.
- Professional applications with profile photo, resume PDF, skills, experience, service area and availability; administrator review, approval or rejection.
- Repair requests, file attachments, category-matched professional queues, accept/decline, estimates, customer approval and status timeline.
- Marketplace listings reviewed by admin, public-to-signed-in-buyer search, buyer offers, seller offer acceptance, atomic listing sale, and stored printable demo receipts.
- Searchable sample parts catalog with 40+ compatible product/brand/model records, category filters, stock and demo checkout.
- Administrator spare-parts inventory: add and edit catalog details, set prices and stock, and deactivate/reactivate items without erasing order history.
- Assistant chat accepts photo, PDF or text uploads, persists messages and attachment metadata, and sends answers through the server-side OpenAI Responses API when configured.
- Live page updates refresh connected dashboards every 15 seconds so changes are visible across Netlify function instances.

## AI and data

The assistant is disabled until `OPENAI_API_KEY` is set. Answers are preliminary and may be wrong; they are not confirmed diagnoses. A server-side safety rule blocks dangerous repair topics, with additional safety instructions sent to the model. Images, PDFs, and text submitted to the assistant are sent to the configured OpenAI API to answer the user. Do not upload sensitive documents. The API key stays in `.env` on the server, never in front-end code.

MongoDB stores account profiles, session hashes and expiry, professional applications, service requests and status history, listing and offer records, orders/receipts, part inventory, assistant conversation records, settings, and uploaded file metadata/content. Passwords are stored as bcrypt hashes, not as readable values.

## Deployment

This project includes a Netlify Functions adapter (`netlify/functions/api.js`) and `netlify.toml`; Netlify serves `public/` and routes `/api/*` through the Express API. Its serverless runtime requires a cloud MongoDB URI (for example, a MongoDB Atlas connection string). The MongoDB server installed on your computer is private to that computer and cannot be reached by the public Netlify site.

Before publishing, add these as private site environment variables in Netlify: `MONGODB_URI`, `MONGODB_DB`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `NODE_ENV=production`. Add `OPENAI_API_KEY` only if you want AI answers. Never put real secrets in `netlify.toml`, browser code, Git, or a public ZIP. In the project directory run `npm install`, authenticate the Netlify CLI with `npx netlify-cli login`, link the site with `npx netlify-cli link`, then publish with `npx netlify-cli deploy --prod`. The sample `netlify.toml` already sets the publish and function directories. Netlify uploads are capped to 3 MB per file to stay within the synchronous function request size.

The demo checkout does not process money. Its receipt only records a simulated purchase and does not prove payment or transfer of legal ownership. Identity and ownership are not verified. The professional approval screen is an admin workflow, not real-world credential verification.

## API basics

- `GET /api/health` — MongoDB connectivity status.
- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me` — account access.
- `GET/POST /api/requests` — customer requests and role-filtered job queues.
- `/api/market/listings`, `/api/market/listings/:id/offers`, `/api/offers/:id/accept` — marketplace flows.
- `GET /api/parts?q=&category=&product=` — searchable spare parts.
- `/api/admin/*` — review queues, overview and commission setting.
- `GET /api/events` — authenticated live updates.
