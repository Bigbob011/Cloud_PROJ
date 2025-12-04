📚 BooksAPI – Azure Cloud Project

README

This project implements a fully serverless, secure, scalable Books REST API using:

Azure Functions (Python) – HTTP-triggered endpoints

Azure SQL Database – persistent storage

Azure Key Vault – secure API key storage

Managed Identity – secure auth between Function App ↔ SQL ↔ Key Vault

Application Insights – observability, metrics, dashboards, KQL

Logic App Automation – scheduled archival validation

The API supports CRUD operations, count, purge, and batch validation of books.

📁 Project Structure
function_app.py         # Main Azure Function App (all endpoints)
local.settings.json     # Local environment config (not used in Azure)
requirements.txt        # Python package dependencies
README.md               # Documentation (this file)

⚙️ Environment Variables

The Function App uses the following configuration settings.
Local values come from local.settings.json; Azure uses Application Settings.

| Setting name               | Example value                               | Purpose                                                                                          |
| -------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `FUNCTIONS_WORKER_RUNTIME` | `python`                                    | Azure Functions runtime                                                                          |
| `AzureWebJobsStorage`      | (connection string)                         | Required by Functions runtime                                                                    |
| `API_KEY`                  | `mysecretkey123`                            | Local fallback API key used when Key Vault is disabled or unavailable                            |
| `KEYVAULT_URL`             | `https://myappkeyv.vault.azure.net/`        | URL of the Key Vault that stores the API key                                                     |
| `API_KEY_SECRET_NAME`      | `BooksApiKey`                               | Name of the secret in Key Vault that contains the API key                                        |
| `USE_KEYVAULT`             | `true` or `false`                           | Toggle for using Key Vault (`true` in Azure, `false` locally)                                    |
| `USE_SQL`                  | `true` or `false`                           | When `true`, the API uses Azure SQL instead of in-memory storage                                 |
| `SQL_SERVER`               | `myserverss.database.windows.net`           | Azure SQL server name (no `https`, just the DNS name)                                            |
| `SQL_DATABASE`             | `MyDB`                                      | Name of the database containing the `dbo.Books` table                                            |
| `SQL_CONNECTION_STRING`    | *(optional)*                                | Left from an earlier version; current code uses `SQL_SERVER` + `SQL_DATABASE` + Managed Identity |
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

🔐 Authentication Flow

Azure (production):
USE_KEYVAULT=true → API key retrieved with DefaultAzureCredential + Key Vault → cached
SQL authentication uses Managed Identity—no passwords.

Local development:
USE_KEYVAULT=false → API key read from API_KEY in local settings.

📘 Book Data Model
JSON Shape Returned by API
{
  "id": "a0a1f922-4b1f-4c80-9a2f-55d3ebf045d1",
  "title": "Example Book",
  "author": "Jane Doe",
  "isbn": "978-1234567890",
  "publisher": "Example Press",
  "year": 2020,
  "description": "A sample book.",
  "archived": false
}

SQL Schema (dbo.Books)
Column	Type
Id	uniqueidentifier (PK)
Title	nvarchar(255)
Author	nvarchar(255)
Isbn	nvarchar(64)
Publisher	nvarchar(255)
Year	int
Description	nvarchar(max)
Archived	bit


🚀 API Endpoints

All endpoints require:

x-api-key: <your key here>

Base URLs:
Local: http://localhost:7071/api/
Azure: https://theapp1-hhaka7cne0a0g5ed.eastus2-01.azurewebsites.net/api/

1️⃣ GET /api/books

Returns all books.

✔ 200 OK
[
  {
    "id": "UUID",
    "title": "Example Book",
    "author": "Jane Doe",
    "isbn": "978-1234567890",
    "publisher": "Example Press",
    "year": 2020,
    "description": "A sample book.",
    "archived": false
  }
]

2️⃣ POST /api/books

Creates a new book.

Headers:

Content-Type: application/json
x-api-key: ...

Request Example
{
  "title": "New Book",
  "author": "John Smith",
  "isbn": "978-1111111111",
  "publisher": "My Publisher",
  "year": 2024,
  "description": "Created via Thunder Client"
}

✔ 201 Created

Returns the created book with generated UUID.

3️⃣ GET /api/books/{book_id}

Returns a single book by ID.

❌ 404 Not Found
{ "error": "Book not found" }

4️⃣ PUT /api/books/{book_id}

Partial update of any field except id.

❌ Changing the ID is rejected:
{ "error": "Cannot change book id" }

5️⃣ DELETE /api/books/{book_id}

Deletes the book.

✔ 200 OK
{ "message": "Deleted successfully" }

6️⃣ GET /api/books/count

Returns number of books.

✔ Example Response
{ "count": 42 }

7️⃣ POST /api/books/purge

Deletes all books.

✔ Example Response
{ "message": "All books removed (deleted 10)" }

8️⃣ PATCH /api/books/validate

Batch validation + archival.

Rule:
Books older than 10 years (Year < currentYear - 10) become archived = true.

✔ Example Response
{
  "updatedCount": 3,
  "timestamp": "2025-12-04T07:30:12.345678Z",
  "mode": "sql"
}


📊 Monitoring & Observability (KQL)

The following logs tables are used:

AppRequests

AppMetrics

AppPerformanceCounters

AppTraces

Example Query (Validate Endpoint Metrics)
AppRequests
| where Name has "/api/books/validate"
| summarize 
    calls=count(),
    failures=countif(Success == false),
    avgDurationMs=avg(DurationMs)
    by bin(TimeGenerated, 1h)
| render timechart


These queries power the dashboard tiles:

Total API Hits

Server Requests

Validation Job Success Count

API Latency

SQL Diagnostics


🔄 Automation (Logic App)

A daily Logic App calls:

PATCH /api/books/validate


This ensures books older than 10 years are automatically archived.


🔐 Security Summary

API key stored in Key Vault

Function App authenticates via Managed Identity

SQL Database firewall locked down

No secrets stored in code

All endpoints require x-api-key


🧪 Local Development

Install Azure Functions Core Tools

Create virtual environment

Install requirements:

pip install -r requirements.txt


Run:

func start


Use Thunder Client / Postman with header:

x-api-key: <local API_KEY>


📦 Deployment

Use:

func azure functionapp publish theapp1-hhaka7cne0a0g5ed


Ensure:

You are logged in (az login)

Your Function App exists

Environment variables are set in Azure

