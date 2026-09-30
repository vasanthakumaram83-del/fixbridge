# FixBridge: Netlify quick start

`http://localhost:3000` is a local address on your laptop; Netlify cannot publish that address directly. Netlify deploys this project's `public/` website and `netlify/functions/` API as a hosted site.

## Publish the project

1. Install Node.js 20 or newer, extract this project folder, and open it in VS Code.
2. In the VS Code terminal, run `npm install`.
3. Link this folder to your Netlify site:

   ```powershell
   npx netlify login
   npx netlify link --id 398e066f-6148-493e-8bb7-00757eccc685
   ```

   The site name is `fixbridge-full-project-demo`. If you deploy to a different site, select that site when linking.

4. Create a MongoDB Atlas database and database user. In Netlify, open **Project configuration → Environment variables** and add:

   | Name | Value |
   |---|---|
   | `MONGODB_URI` | Your private Atlas connection URI (`mongodb+srv://...`) |
   | `MONGODB_DB` | `fixbridge` |
   | `ADMIN_EMAIL` | The administrator email you want to use |
   | `ADMIN_PASSWORD` | A unique password of at least 10 characters |
   | `NODE_ENV` | `production` |

   Add `OPENAI_API_KEY` only if you have an API key and want live AI responses. Never paste secrets into this guide, browser code, Git, or a ZIP file. The local MongoDB address (`127.0.0.1`) will not work from Netlify. Configure Atlas network access for the hosted function.

5. Publish from the project folder:

   ```powershell
   npm run netlify:deploy
   ```

6. Open the production URL shown by Netlify. The current site address is <https://fixbridge-full-project-demo.netlify.app/>.

## Notes

- Netlify Drop/drag-and-drop only uploads static files; use the Netlify CLI or a Git-connected build so the API function is deployed too.
- Customer, professional, and administrator accounts are stored in MongoDB. Professional accounts remain unavailable for sign-in until an administrator approves them.
- Payments and orders are demos. Netlify function uploads are limited to 3 MB per file in this project.
- Keep `.env` private for local development. This handoff ZIP includes `.env.example`, not your local `.env`.
