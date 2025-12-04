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

# Should this app use Azure SQL instead of in-memory list?
USE_SQL = os.getenv("USE_SQL", "false").lower() == "true"

# If SQL is requested but pyodbc is missing, fall back to in-memory
if USE_SQL and pyodbc is None:
    logging.warning(
        "USE_SQL is true but pyodbc is not installed. "
        "Falling back to in-memory books store for this environment."
    )
    USE_SQL = False



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
    Create a SQL connection using Managed Identity (no passwords).

    - Uses DefaultAzureCredential, which in Azure Functions resolves to the
      Function App's managed identity.
    - Requests an access token for Azure SQL.
    - Uses pyodbc with an access token instead of username/password.

    Returns:
        pyodbc.Connection

    Raises:
        RuntimeError / Exception if configuration is missing or the token/connection fails.
    """
    if not USE_SQL:
        raise RuntimeError("USE_SQL is false – SQL connection not enabled in this environment.")

    # Ask Azure for an access token to talk to Azure SQL
    token = _sql_credential.get_token("https://database.windows.net/.default")

    # Build the basic connection string (no user/password)
    conn_str = (
        f"Driver={SQL_DRIVER};"
        f"Server=tcp:{SQL_SERVER},1433;"
        f"Database={SQL_DATABASE};"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
        "Connection Timeout=30;"
    )

    # Azure SQL expects the access token encoded as UTF-16-LE
    token_bytes = token.token.encode("utf-16-le")

    conn = pyodbc.connect(
        conn_str,
        attrs_before={SQL_COPT_SS_ACCESS_TOKEN: token_bytes}
    )

    return conn

def db_insert_book(book: dict) -> dict:
    """
    Insert a new book into dbo.Books and return the book with its new ID.
    Expects keys: title, author, isbn, publisher, year, description.
    """
    with get_sql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dbo.Books (Title, Author, Isbn, Publisher, Year, Description)
                OUTPUT INSERTED.BookId
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                book["title"],
                book["author"],
                book["isbn"],
                book["publisher"],
                book["year"],
                book["description"],
            )
            row = cur.fetchone()
            conn.commit()

    book["id"] = str(row[0])
    return book


def db_get_all_books() -> list[dict]:
    """
    Read all books from dbo.Books and return them as a list of dicts.
    """
    with get_sql_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT BookId, Title, Author, Isbn, Publisher, Year, Description
                FROM dbo.Books
                ORDER BY CreatedAt DESC
                """
            )
            rows = cur.fetchall()

    result = []
    for r in rows:
        result.append(
            {
                "id": str(r[0]),
                "title": r[1],
                "author": r[2],
                "isbn": r[3],
                "publisher": r[4],
                "year": int(r[5]) if r[5] is not None else None,
                "description": r[6],
            }
        )
    return result



# =========================================================
#  3. Main Collection Endpoints (/books)
# =========================================================

@app.function_name(name="BooksAPI")
@app.route(route="books", methods=["GET", "POST"])
def books_api(req: func.HttpRequest) -> func.HttpResponse:
    """
    Handle GET (list all books) and POST (add new book) requests.
    This endpoint operates on the full collection.
    """
    logging.info("📘 BooksAPI invoked: %s", req.method)

    # --- Authentication ---
    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    # --- POST: Create a new book record ---
    if req.method == "POST":
        if not require_json_content(req):
            return error_response("Content-Type must be application/json", 400)
        try:
            body = req.get_json()
        except ValueError:
            return error_response("Invalid JSON body", 400)

        valid, err = validate_book_schema(body, True)
        if not valid:
            return error_response(err, 400)

        # Assign a unique ID and append safely
        book = dict(body)
        book["id"] = str(uuid.uuid4())
        with books_lock:
            books.append(book)

        return json_response(book, 201)

    # --- GET: Retrieve all stored books ---
    elif req.method == "GET":
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
    """Return the total number of books in memory."""
    if not check_api_key(req):
        return error_response("Unauthorized", 401)
    with books_lock:
        n = len(books)
    return json_response({"count": n}, 200)


@app.function_name(name="BooksPurgeAPI")
@app.route(route="books/purge", methods=["POST"])
def books_purge_api(req: func.HttpRequest) -> func.HttpResponse:
    """Clear all books from memory (for testing or resets)."""
    if not check_api_key(req):
        return error_response("Unauthorized", 401)
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
    Handle GET, PUT, and DELETE requests for a specific book.
    Book is identified by its unique UUID in the route.
    """
    logging.info("📗 BooksByIdAPI invoked: %s", req.method)

    # --- Authentication ---
    if not check_api_key(req):
        return error_response("Unauthorized", 401)

    # --- Route parameter ---
    book_id = req.route_params.get("book_id")
    if not book_id:
        return error_response("Missing book_id in route", 400)

    # --- Fix for overlapping routes (count, purge) ---
    if book_id == "count" and req.method == "GET":
        return books_count_api(req)
    if book_id == "purge" and req.method == "POST":
        return books_purge_api(req)

    # --- GET: Retrieve a specific book ---
    if req.method == "GET":
        with books_lock:
            for b in books:
                if b.get("id") == book_id:
                    return json_response(b, 200)
        return error_response("Book not found", 404)

    # --- PUT: Update an existing book ---
    if req.method == "PUT":
        if not require_json_content(req):
            return error_response("Content-Type must be application/json", 400)
        try:
            body = req.get_json()
        except ValueError:
            return error_response("Invalid JSON body", 400)

        valid, err = validate_book_schema(body, False)
        if not valid:
            return error_response(err, 400)

        with books_lock:
            idx = find_book_index(book_id)
            if idx == -1:
                return error_response("Book not found", 404)

            if "id" in body and body["id"] != book_id:
                return error_response("Cannot change book id", 400)

            books[idx].update(body)
            updated = books[idx].copy()
        return json_response(updated, 200)

    # --- DELETE: Remove a book by ID ---
    if req.method == "DELETE":
        with books_lock:
            idx = find_book_index(book_id)
            if idx == -1:
                return error_response("Book not found", 404)
            books.pop(idx)
        return json_response({"message": "Deleted successfully"}, 200)

    return error_response("Method not allowed", 405)


# EOF ---------------------------------------------------------

# class code start -- private readonly defaultazure credentail credential = new();
# "az login" in terminal to log you in for local host. in not know what az is install azure CLI 