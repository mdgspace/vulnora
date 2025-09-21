# Vulnora

**Advanced Web Application Security Scanner**

**Vulnora** is a full-stack web application that helps developers and
security researchers **identify common vulnerabilities** in web
applications and provides **actionable recommendations** for mitigation.

With an intuitive dashboard, users can select attack vectors (e.g., SQL
Injection, XSS, CSRF, DDoS, etc.), run tests on target domains, and
receive **structured vulnerability reports** enriched with best
practices using an **LLM-powered assistant**.

------------------------------------------------------------------------

## ✨ Features

-   🎯 **Targeted Security Scans** -- Run multiple vulnerability checks
    on any domain.
-   🛡️ **Supported Attack Vectors**:
    -   SQL Injection (Critical)
    -   Cross-Site Scripting (XSS)
    -   Cross-Site Request Forgery (CSRF)
    -   Directory Traversal
    -   Insecure Deserialization
    -   Command Injection
    -   JWT Manipulation
    -   File Upload Vulnerabilities
    -   DDoS Attack Simulation
-   📊 **History Dashboard** -- View past reports and track
    vulnerabilities over time.
-   🤖 **LLM Integration** -- Attack results are enhanced with
    structured descriptions and **fix recommendations** (via HuggingFace
    API).
-   📂 **Report Storage** -- All scans saved in MongoDB for easy
    retrieval.
-   🐳 **Fully Dockerized** -- Single command spin-up with
    `docker compose`.

------------------------------------------------------------------------

## 🏗️ Architecture

-   **Frontend** -- React + Vite + TailwindCSS + Axios\
-   **Auth Server (Go)** -- Authentication & request routing
    (JWT-based)\
-   **Flask Server (Python)** -- Executes most vulnerability tests\
-   **Go Server** -- Handles high-performance DDoS attack simulation\
-   **MongoDB** -- Stores attack reports and user history\
-   **LLM (HuggingFace API)** -- Formats results into structured reports
    with remediation advice

------------------------------------------------------------------------

## 📂 Project Structure

    VULNORA/
    ├── auth-server/        # Go-based authentication server (JWT, routing)
    ├── flask-server/       # Python Flask server for attack execution
    ├── go-server/          # Go server handling DDoS load tests
    ├── frontend/           # React + Vite + Tailwind client app
    ├── docker-compose.yml  # Orchestration of all services
    └── requirements.txt    # Python deps for Flask server

------------------------------------------------------------------------

## 🚀 Getting Started

### Prerequisites

-   [Docker](https://docs.docker.com/get-docker/) installed
-   HuggingFace API key (for LLM integration)
-   MongoDB (pulled via Docker automatically)

### Setup

``` bash
# 1. Clone the repository
git clone https://github.com/your-username/vulnora.git
cd vulnora

# 2. Configure environment files
create `.env` files in each service directory taking reference from `.env.sample` files
# Add Mongo URI, JWT secret, HuggingFace API key, etc.

# 3. Start all services
docker compose up

# 4. Access the frontend
http://localhost:5173
```

### Service Ports

-   Frontend → `5173`
-   Auth Server (Go) → `3000`
-   Flask Server (Python) → `5001`
-   Go Server (DDoS) → `8080`

------------------------------------------------------------------------

## 🛠️ Tech Stack

-   **Frontend**: React, Vite, TailwindCSS, Axios
-   **Backend**:
    -   Go (Gin Router) -- Auth & DDoS services
    -   Flask (Python) -- Vulnerability testing
-   **Database**: MongoDB
-   **Auth**: JWT
-   **LLM**: HuggingFace API
-   **Deployment**: Docker & Docker Compose

------------------------------------------------------------------------

## 🧩 Future Enhancements

-   🔍 Add more vulnerability checks (e.g., SSRF, Open Redirects).
-   📑 Export reports (PDF/CSV).
-   🌐 Cloud deployment (Kubernetes, AWS).

------------------------------------------------------------------------

## 🤝 Contributing

Contributions are welcome! 🎉

1.  Fork the repo
2.  Create a feature branch (`git checkout -b feature-name`)
3.  Commit changes (`git commit -m "Add feature"`)
4.  Push branch (`git push origin feature-name`)
5.  Open a PR

------------------------------------------------------------------------
