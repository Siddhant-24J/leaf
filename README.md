# Leaf – Leave & WFH Manager

A lightweight, production-ready Leave & Work-From-Home (WFH) management system built with FastAPI (Python) and a single-page HTML/CSS/JS frontend.

---

## 🚀 Easy 1-Click Deployment (Recommended: Render)

The easiest and most reliable free/low-cost platform to deploy Leaf is **[Render](https://render.com)**.

### Why Render?
- **Automatic updates:** Every time you push changes to GitHub (`git push origin main`), Render rebuilds and updates your live site automatically in 60 seconds with zero downtime.
- **Free automatic SSL/HTTPS** (`https://your-app.onrender.com`).
- **Persistent Disk support** so your SQLite database is never lost across deploys.

### How to Deploy (5 Steps):
1. **Push your code to GitHub**:
   - Create a GitHub repository (e.g. `leaf-app`).
   - Push this codebase to your repository.
2. **Create a Free Account on [Render.com](https://render.com)**.
3. **Click `New +` → `Web Service`**:
   - Connect your GitHub repository.
   - Select **Python** runtime.
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. **Add Environment Variables** (under *Advanced* or *Environment*):
   - `SECRET_KEY`: *(Generate a 48+ char random string)*
   - `ADMIN_EMAIL`: `your-email@gmail.com`
   - `ADMIN_PASSWORD`: *(A strong admin password)*
   - `COOKIE_SECURE`: `true`
   - `TZ_NAME`: `Asia/Kolkata` (or your timezone)
   - `GOOGLE_CLIENT_ID`: *(Optional - add your Google OAuth Client ID)*
   - `DB_PATH`: `/var/data/leave.db`
5. **Attach a Persistent Disk** (Under *Disks* tab):
   - Name: `leave-data`
   - Mount Path: `/var/data`
   - Size: `1 GB`
6. Click **Deploy Web Service**! Your app will be live at `https://your-app.onrender.com`.

---

## 🔄 How to Update After Deployment

Updating your app is completely automated:
1. Make your code changes locally.
2. Commit and push to GitHub:
   ```bash
   git add .
   git commit -m "Your update description"
   git push origin main
   ```
3. **Render detects the push and automatically redeploys your updated app within 1 minute!**

---

## 💻 Run Locally

```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --env-file .env --port 8000
```
Open **[http://localhost:8000](http://localhost:8000)**.

---

## 🔐 Authentication
- **Admin**: Sign in with `ADMIN_EMAIL` + `ADMIN_PASSWORD` or with Google.
- **Employees**: Added by admin under **Admin** → **Give someone access** by email. On their first login (via Google or admin invite), they are prompted to create their personal password, allowing them to also sign in directly using email and password. Employees can update their password anytime from their dashboard sidebar.
