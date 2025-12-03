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


# =========================================================
#  1. Application Initialization
# =========================================================

# Define the Azure Function app with anonymous HTTP access
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# Thread-safe in-memory storage for books
books = []
books_lock = Lock()

# API Key (set via environment variable or defaults for local testing)
API_KEY = os.getenv("API_KEY", "mysecretkey123")

# Required fields for book schema validation
REQUIRED_FIELDS = ["title", "author", "isbn", "publisher", "year", "description"]


# =========================================================
#  2. Helper Functions
# =========================================================

def json_response(payload, status=200):
    """Return a consistent JSON HTTP response."""
    return func.HttpResponse(json.dumps(payload), status_code=status, mimetype="application/json")


def error_response(message, status=400):
    """Shortcut to return an error JSON response with a message."""
    return json_response({"error": message}, status)


def check_api_key(req: func.HttpRequest) -> bool:
    """Verify the presence and validity of the x-api-key header."""
    return req.headers.get("x-api-key") == API_KEY


def require_json_content(req: func.HttpRequest):
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


def find_book_index(book_id: str):
    """Find and return the index of a book by its unique ID."""
    for i, b in enumerate(books):
        if b.get("id") == book_id:
            return i
    return -1


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