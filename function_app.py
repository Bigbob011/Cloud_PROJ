# ---------------------------------------------------------
# BooksAPI – Cloud Computing Midterm Project
# Author: Braden Mackey
# Course: CSE 300 - Cloud Computing
# Date: October 2025
#
# Description:
#   A RESTful Azure Function API for managing book records.
#   Implements full CRUD functionality with in-memory storage,
#   thread-safe operations, and simple API key authentication.
#   Includes utility endpoints for counting and purging data.
# ---------------------------------------------------------

import os
import json
import uuid
import logging
from threading import Lock
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from datetime import datetime 


# so pyodbc dosent crash local testing because it exists in azure but not locally
try: 
    import pyodbc # type: ignore
except ImportError:
    pyodbc = None  # pyodbc is not available




# =========================================================
#  1. Application Initialization
# =========================================================

# Define the Azure Function app with anonymous HTTP access
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Thread-safe in-memory storage for books
books = []
books_lock = Lock()

# -----------------------
# Config / environment
# -----------------------

logger = logging.getLogger("booksapi")

# Local fallback key (used locally and as a fallback on Azure)
LOCAL_API_KEY = os.getenv("API_KEY", "mysecretkey123")

# Key Vault integration flags
KEYVAULT_URL = os.getenv("KEYVAULT_URL")  # e.g. https://myappkeyv.vault.azure.net/
API_KEY_SECRET_NAME = os.getenv("API_KEY_SECRET_NAME", "BooksApiKey")
USE_KEYVAULT = os.getenv("USE_KEYVAULT", "false").lower() == "true"

# Required fields for book schema validation
REQUIRED_FIELDS = ["title", "author", "isbn", "publisher", "year", "description"]

# Cache for the API key so we don't call Key Vault on every request
_cached_api_key: str | None = None

# When USE_SQL == "true" (string, case-insensitive), API will use Azure SQL
USE_SQL = os.getenv("USE_SQL", "false").lower() == "true"

# SQL connection configuration (used only if USE_SQL is true)
SQL_SERVER = os.getenv("SQL_SERVER")  # e.g. "myserverss.database.windows.net"
SQL_DATABASE = os.getenv("SQL_DATABASE")  # e.g. "MyDB"
SQL_DRIVER = os.getenv("SQL_DRIVER", "{ODBC Driver 18 for SQL Server}")

# Connection string for Azure SQL (managed identity / AAD)
SQL_CONNECTION_STRING = os.getenv("SQL_CONNECTION_STRING")

# If SQL is requested but pyodbc is missing, fall back to in-memory
if USE_SQL and pyodbc is None:
    logging.warning(
        "USE_SQL is true but pyodbc is not installed. "
        "Falling back to in-memory books store for this environment."
    )
    USE_SQL = False

# =========================================================
#  SQL configuration (Azure SQL vs in-memory toggle)
# =========================================================

# When USE_SQL == "true" (string, case-insensitive), API will use Azure SQL
USE_SQL = os.getenv("USE_SQL", "false").lower() == "true"

# Connection string for Azure SQL (managed identity / AAD)
SQL_CONNECTION_STRING = os.getenv("SQL_CONNECTION_STRING")

def row_to_book(row):
    """
    Convert a SQL row from dbo.Books into the JSON shape used by the API.
    Assumes SELECT order:
      Id, Title, Author, Isbn, Publisher, [Year], [Description], Archived
    """
    # Access by index so we don't care about column name casing
    return {
        "id": str(row[0]),
        "title": row[1],
        "author": row[2],
        "isbn": row[3],
        "publisher": row[4],
        "year": int(row[5]) if row[5] is not None else None,
        "description": row[6],
        "archived": bool(row[7]) if len(row) > 7 else False,
    }

# =========================================================
#  SQL helper functions for Books
# =========================================================


def sql_insert_book(book_data: dict) -> dict:
    """
    Insert a book into dbo.Books and return the full book (with generated ID).
    """
    new_id = str(uuid.uuid4())

    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dbo.Books (Id, Title, Author, Isbn, Publisher, [Year], [Description], Archived)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            new_id,
            book_data["title"],
            book_data["author"],
            book_data["isbn"],
            book_data["publisher"],
            book_data["year"],
            book_data["description"],
        )
        conn.commit()

    result = dict(book_data)
    result["id"] = new_id
    result["archived"] = False
    return result


def sql_get_all_books() -> list:
    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT Id, Title, Author, Isbn, Publisher, [Year], [Description], Archived
            FROM dbo.Books
            ORDER BY Title
            """
        )
        rows = cur.fetchall()
    return [row_to_book(r) for r in rows]


def sql_get_book_by_id(book_id: str):
    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT Id, Title, Author, Isbn, Publisher, [Year], [Description], Archived
            FROM dbo.Books
            WHERE Id = ?
            """,
            book_id,
        )
        row = cur.fetchone()
    return row_to_book(row) if row else None


def sql_update_book(book_id: str, patch: dict):
    """
    Apply a partial update to a book row.
    Only updates fields present in `patch`.
    """
    # Map JSON field names to SQL column names
    field_map = {
        "title": "Title",
        "author": "Author",
        "isbn": "Isbn",
        "publisher": "Publisher",
        "year": "Year",
        "description": "Description",
    }

    set_clauses = []
    params = []

    for json_field, column in field_map.items():
        if json_field in patch:
            set_clauses.append(f"{column} = ?")
            params.append(patch[json_field])

    if not set_clauses:
        # Nothing to update
        return sql_get_book_by_id(book_id)

    params.append(book_id)
    sql = "UPDATE dbo.Books SET " + ", ".join(set_clauses) + " WHERE Id = ?"

    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()

    return sql_get_book_by_id(book_id)


def sql_delete_book(book_id: str) -> int:
    """
    Delete a book. Returns number of rows affected (0 or 1).
    """
    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM dbo.Books WHERE Id = ?", book_id)
        affected = cur.rowcount
        conn.commit()
    return affected


def sql_get_book_count() -> int:
    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM dbo.Books")
        (count,) = cur.fetchone()
    return int(count)
    

def sql_validate_books() -> int:
    """
    Validation rule for books:
      - If Year < (currentYear - 10), mark Archived = 1.

    Returns the number of rows updated.
    """
    from datetime import datetime

    current_year = datetime.utcnow().year
    cutoff_year = current_year - 10

    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE dbo.Books
            SET Archived = 1
            WHERE [Year] IS NOT NULL
              AND [Year] < ?
              AND (Archived = 0 OR Archived IS NULL)
            """,
            cutoff_year,
        )
        affected = cur.rowcount
        conn.commit()

    return int(affected)


def sql_purge_books() -> int:
    """
    Delete all books. Returns number of rows deleted.
    """
    with get_sql_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM dbo.Books")
        affected = cur.rowcount
        conn.commit()
    return affected


# =========================================================
#  2. Helper Functions
# =========================================================


def json_response(payload, status: int = 200) -> func.HttpResponse:
    """Return a consistent JSON HTTP response."""
    return func.HttpResponse(
        json.dumps(payload),
        status_code=status,
        mimetype="application/json",
    )


def error_response(message: str, status: int = 400) -> func.HttpResponse:
    """Shortcut to return an error JSON response with a message."""
    return json_response({"error": message}, status)


def get_api_key() -> str:
    """
    Get the API key used to authenticate callers.

    Order of precedence:
    1. If USE_KEYVAULT is true and KEYVAULT_URL is set:
         - use DefaultAzureCredential + SecretClient to get the secret.
         - cache it in _cached_api_key.
    2. If anything fails or USE_KEYVAULT is false:
         - fall back to LOCAL_API_KEY (from environment).
    """
    global _cached_api_key

    # If Key Vault is enabled and we have a URL, try to use it
    if USE_KEYVAULT and KEYVAULT_URL:
        # Use cached value if already retrieved
        if _cached_api_key:
            return _cached_api_key

        try:
            # Managed Identity (on Azure) or local dev credentials
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=KEYVAULT_URL, credential=credential)

            secret = client.get_secret(API_KEY_SECRET_NAME)
            _cached_api_key = secret.value

            # NOTE: Do NOT log the actual key, just that we succeeded
            logging.info("🔐 API key successfully retrieved from Key Vault secret '%s'.",
                         API_KEY_SECRET_NAME)

            return _cached_api_key

        except Exception as ex:
            # Log the failure but do not stop the app; fall back to local key
            logging.error(
                "❌ Failed to retrieve API key from Key Vault (%s). Falling back to LOCAL_API_KEY. Error: %s",
                API_KEY_SECRET_NAME,
                ex,
            )

    # Either USE_KEYVAULT is false, or Key Vault retrieval failed
    if LOCAL_API_KEY:
        logging.info("🔑 Using LOCAL_API_KEY value (Key Vault disabled or unavailable).")
        return LOCAL_API_KEY

    # As a last resort, return an empty string
    logging.warning("⚠ No API key available (LOCAL_API_KEY not set). All requests will be unauthorized.")
    return ""


def check_api_key(req: func.HttpRequest) -> bool:
    """
    Verify the presence and validity of the x-api-key header.

    - Reads the expected key via get_api_key() (from Key Vault or local).
    - Compares it to the 'x-api-key' header.
    """
    expected_key = get_api_key()
    provided_key = req.headers.get("x-api-key")

    # Don't log actual keys; just log whether they matched
    if not provided_key:
        logging.warning("🚫 Missing x-api-key header in request.")
        return False

    match = (provided_key == expected_key)
    logging.info("🔐 API key check result: %s", "MATCH" if match else "NO MATCH")
    return match


def require_json_content(req: func.HttpRequest) -> bool:
    """Ensure the Content-Type header indicates JSON data."""
    ct = req.headers.get("content-type", "")
    return "application/json" in ct.lower()


def validate_book_schema(data: dict, require_all: bool = True):
    """
    Validate the JSON structure for a book object.
    If require_all=True, all fields must be present.
    """
    if not isinstance(data, dict):
        return False, "Body must be a JSON object"

    if require_all:
        for f in REQUIRED_FIELDS:
            if f not in data:
                return False, f"Missing required field: {f}"

    # Validate 'year' if present
    if "year" in data:
        try:
            data["year"] = int(data["year"])
        except Exception:
            return False, "Field 'year' must be an integer"

    return True, None


def find_book_index(book_id: str) -> int:
    """Find and return the index of a book by its unique ID."""
    for i, b in enumerate(books):
        if b.get("id") == book_id:
            return i
    return -1

def get_sql_connection():
    """
    Open a connection to Azure SQL.
    - On Azure: uses Managed Identity (ActiveDirectoryMsi)
    - Locally: we *do not* use SQL; local runs stay in-memory.
    """
    if not USE_SQL:
        raise RuntimeError("SQL is not enabled (USE_SQL is false)")

    if pyodbc is None:
        raise RuntimeError("pyodbc is not available, cannot use SQL")

    if not SQL_SERVER or not SQL_DATABASE:
        raise RuntimeError("SQL_SERVER or SQL_DATABASE not configured")

    conn_str = (
        f"Driver={SQL_DRIVER};"
        f"Server=tcp:{SQL_SERVER},1433;"
        f"Database={SQL_DATABASE};"
        "Authentication=ActiveDirectoryMsi;"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
    )

    # Short timeout so failures surface quickly
    return pyodbc.connect(conn_str, timeout=5)


def db_insert_book(book: dict) -> dict:
    """
    Insert a book into the Azure SQL 'Books' table.

    Expects a dict with keys:
    title, author, isbn, publisher, year, description

    Returns the same dict with an 'id' field (UUID string).
    """
    if not USE_SQL:
        raise RuntimeError("db_insert_book called while USE_SQL is false")

    # Generate ID in code to keep it simple
    book_id = str(uuid.uuid4())

    # Ensure 'year' is int (validate_book_schema should already have done this)
    year_value = int(book["year"])

    conn = get_sql_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO Books (Id, Title, Author, Isbn, Publisher, Year, Description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    book_id,
                    book["title"],
                    book["author"],
                    book["isbn"],
                    book["publisher"],
                    year_value,
                    book["description"],
                ),
            )
            conn.commit()
    finally:
        conn.close()

    # Return a full book dict including the ID we assigned
    result = dict(book)
    result["id"] = book_id
    return result

def db_get_all_books() -> list[dict]:
    """
    Fetch all books from the Azure SQL 'Books' table
    and return them as a list of dicts.
    """
    if not USE_SQL:
        raise RuntimeError("db_get_all_books called while USE_SQL is false")

    conn = get_sql_connection()
    books_from_db: list[dict] = []

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT Id, Title, Author, Isbn, Publisher, Year, Description
                FROM Books
                """
            )
            rows = cur.fetchall()
            for row in rows:
                books_from_db.append(
                    {
                        "id": str(row.Id),
                        "title": row.Title,
                        "author": row.Author,
                        "isbn": row.Isbn,
                        "publisher": row.Publisher,
                        "year": int(row.Year) if row.Year is not None else None,
                        "description": row.Description,
                    }
                )
    finally:
        conn.close()

    return books_from_db



# =========================================================
#  3. Main Collection Endpoints (/books)
# =========================================================

@app.function_name(name="BooksAPI")
@app.route(route="books", methods=["GET", "POST"])
def books_api(req: func.HttpRequest) -> func.HttpResponse:
    """
    Handle:
      - GET /api/books   -> list all books
      - POST /api/books  -> create a new book

    Uses Azure SQL when USE_SQL is true, otherwise falls back to in-memory list.
    """
    logging.info("📘 BooksAPI invoked: %s", req.method)

    # --- Authentication ---
    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    # ---------- POST: create ----------
    if req.method == "POST":
        if not require_json_content(req):
            return error_response("Content-Type must be application/json", 400)
        try:
            body = req.get_json()
        except ValueError:
            return error_response("Invalid JSON body", 400)

        valid, err = validate_book_schema(body, require_all=True)
        if not valid:
            return error_response(err, 400)

        # SQL path
        if USE_SQL:
            try:
                new_book = sql_insert_book(body)
                return json_response(new_book, 201)
            except Exception as ex:
                logging.exception("Error inserting book into SQL")
                return error_response(f"Database error: {ex}", 500)

        # In-memory fallback (local dev without SQL)
        book = dict(body)
        book["id"] = str(uuid.uuid4())
        with books_lock:
            books.append(book)
        return json_response(book, 201)

    # ---------- GET: list all ----------
    if req.method == "GET":
        if USE_SQL:
            try:
                all_books = sql_get_all_books()
                return json_response(all_books, 200)
            except Exception as ex:
                logging.exception("Error querying books from SQL")
                return error_response(f"Database error: {ex}", 500)

        # In-memory fallback
        with books_lock:
            copy = list(books)
        return json_response(copy, 200)

    return error_response("Method not allowed", 405)

# =========================================================
#  4. Utility Endpoints (/books/count, /books/purge)
# =========================================================

@app.function_name(name="BooksCountAPI")
@app.route(route="books/count", methods=["GET"])
def books_count_api(req: func.HttpRequest) -> func.HttpResponse:
    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    if USE_SQL:
        try:
            n = sql_get_book_count()
        except Exception as ex:
            logging.exception("Error counting books in SQL")
            return error_response(f"Database error: {ex}", 500)
        return json_response({"count": n}, 200)

    with books_lock:
        n = len(books)
    return json_response({"count": n}, 200)



@app.function_name(name="BooksPurgeAPI")
@app.route(route="books/purge", methods=["POST"])
def books_purge_api(req: func.HttpRequest) -> func.HttpResponse:
    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    if USE_SQL:
        try:
            deleted = sql_purge_books()
        except Exception as ex:
            logging.exception("Error purging books in SQL")
            return error_response(f"Database error: {ex}", 500)
        return json_response({"message": f"All books removed (deleted {deleted})"}, 200)

    with books_lock:
        books.clear()
    return json_response({"message": "All books removed"}, 200)



# =========================================================
#  5. Item-Specific Endpoints (/books/{book_id})
# =========================================================

@app.function_name(name="BooksByIdAPI")
@app.route(route="books/{book_id}", methods=["GET", "PUT", "DELETE"])
def books_by_id_api(req: func.HttpRequest) -> func.HttpResponse:
    """
    Handle GET, PUT, DELETE for a specific book.
    Book is identified by its unique UUID in the route.
    """
    logging.info("📗 BooksByIdAPI invoked: %s", req.method)

    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    book_id = req.route_params.get("book_id")
    if not book_id:
        return error_response("Missing book_id in route", 400)

    # ---------- GET by ID ----------
    if req.method == "GET":
        if USE_SQL:
            try:
                book = sql_get_book_by_id(book_id)
            except Exception as ex:
                logging.exception("Error reading book from SQL")
                return error_response(f"Database error: {ex}", 500)

            if not book:
                return error_response("Book not found", 404)
            return json_response(book, 200)

        # In-memory fallback
        with books_lock:
            for b in books:
                if b.get("id") == book_id:
                    return json_response(b, 200)
        return error_response("Book not found", 404)

    # ---------- PUT (partial update) ----------
    if req.method == "PUT":
        if not require_json_content(req):
            return error_response("Content-Type must be application/json", 400)
        try:
            body = req.get_json()
        except ValueError:
            return error_response("Invalid JSON body", 400)

        valid, err = validate_book_schema(body, require_all=False)
        if not valid:
            return error_response(err, 400)

        if USE_SQL:
            try:
                updated = sql_update_book(book_id, body)
            except Exception as ex:
                logging.exception("Error updating book in SQL")
                return error_response(f"Database error: {ex}", 500)

            if not updated:
                return error_response("Book not found", 404)
            return json_response(updated, 200)

        # In-memory fallback
        with books_lock:
            idx = find_book_index(book_id)
            if idx == -1:
                return error_response("Book not found", 404)

            # Prevent ID changes
            if "id" in body and body["id"] != book_id:
                return error_response("Cannot change book id", 400)

            books[idx].update(body)
            updated = books[idx].copy()
        return json_response(updated, 200)

    # ---------- DELETE ----------
    if req.method == "DELETE":
        if USE_SQL:
            try:
                affected = sql_delete_book(book_id)
            except Exception as ex:
                logging.exception("Error deleting book in SQL")
                return error_response(f"Database error: {ex}", 500)

            if affected == 0:
                return error_response("Book not found", 404)
            return json_response({"message": "Deleted successfully"}, 200)

        # In-memory fallback
        with books_lock:
            idx = find_book_index(book_id)
            if idx == -1:
                return error_response("Book not found", 404)
            books.pop(idx)
        return json_response({"message": "Deleted successfully"}, 200)

    return error_response("Method not allowed", 405)

# =========================================================
#  6. Validation Endpoint (/books/validate)
# =========================================================

@app.function_name(name="BooksValidateAPI")
@app.route(route="books/validate", methods=["PATCH"])
def books_validate_api(req: func.HttpRequest) -> func.HttpResponse:
    """
    PATCH /api/books/validate

    Runs a batch validation over all books.

    SQL mode (USE_SQL = True):
      - Marks books as archived when they are older than 10 years.
        (SET Archived = 1 WHERE year < currentYear - 10)

    In-memory mode (USE_SQL = False, local dev only):
      - Sets an 'archived' flag on items in the in-memory books list.

    Response JSON:
      {
        "updatedCount": <int>,             # number of rows/items updated
        "timestamp": "2025-12-03T17:25Z",  # UTC timestamp when validation completed
        "mode": "sql" | "memory"           # which backing store was used
      }
    """
    logging.info("ValidationTriggered: PATCH /api/books/validate")

    # --- Authentication ---
    if not check_api_key(req):
        logging.warning("ValidationUnauthorized: missing_or_invalid_api_key")
        return error_response("Unauthorized", 401)

    # --- SQL-backed validation path ---
    if USE_SQL:
        try:
            logging.info("ValidationMode: sql")
            updated = sql_validate_books()  # helper that runs the SQL UPDATE and returns affected row count
        except Exception as ex:
            # Log full details to App Insights but return a safe error to the client
            logging.exception("ValidationFailed: SQL validation error")
            return error_response(f"Database error during validation: {ex}", 500)

        payload = {
            "updatedCount": updated,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "mode": "sql",
        }
        logging.info(
            "ValidationCompletedSQL: updatedCount=%d timestamp=%s",
            payload["updatedCount"],
            payload["timestamp"],
        )
        return json_response(payload, 200)

    # --- In-memory fallback (local development without SQL) ---
    logging.info("ValidationMode: memory (in-memory fallback)")

    current_year = datetime.utcnow().year
    cutoff_year = current_year - 10
    updated = 0

    with books_lock:
        for b in books:
            year = b.get("year")
            if year is None:
                continue

            try:
                y = int(year)
            except Exception:
                # Skip items with non-numeric year
                continue

            if y < cutoff_year and not b.get("archived"):
                b["archived"] = True
                updated += 1

    payload = {
        "updatedCount": updated,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "mode": "memory",
    }
    logging.info(
        "ValidationCompletedMemory: updatedCount=%d timestamp=%s",
        payload["updatedCount"],
        payload["timestamp"],
    )
    return json_response(payload, 200)




# EOF ---------------------------------------------------------

# class code start -- private readonly defaultazure credentail credential = new();
# "az login" in terminal to log you in for local host. in not know what az is install azure CLI 