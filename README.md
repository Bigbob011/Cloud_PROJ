# Cloud_PROJ
my cloud final project 

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

In Azure, USE_KEYVAULT=true and KEYVAULT_URL are set.
get_api_key() uses DefaultAzureCredential + SecretClient to read API_KEY_SECRET_NAME once, caches it, and compares it to the x-api-key header.

Locally, USE_KEYVAULT=false and the key is read from API_KEY in local.settings.json.

=========================books================================

A Book in the API has the following JSON shape:

{
  "id": "a0a1f922-4b1f-4c80-9a2f-55d3ebf045d1",
  "title": "Example Book",
  "author": "Jane Doe",
  "isbn": "978-1234567890",
  "publisher": "Example Press",
  "year": 2020,
  "description": "A sample book used for testing.",
  "archived": false
}


In SQL, this maps to dbo.Books columns:
Id (uniqueidentifier), Title, Author, Isbn, Publisher, [Year], [Description], Archived (bit).

--------------------------------------------------------------------------------
====================================ENDPOINTS=====================================
---------------------------------------------------------------------------------

All endpoints are rooted at:

Local: http://localhost:7071/api/...

Azure: https://<your-func-app-name>.azurewebsites.net/api/...

All requests must send: x-api-key: <your key>.

1. GET /api/books

Description:
Return all books.

SQL mode: reads from dbo.Books.
Memory mode: reads from the in-memory list.

Response 200:

[
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
]



2. POST /api/books

Description:
Create a new book.

Headers:

Content-Type: application/json

x-api-key: ...

Request body:

{
  "title": "New Book",
  "author": "John Smith",
  "isbn": "978-1111111111",
  "publisher": "My Publisher",
  "year": 2024,
  "description": "Created via Thunder Client"
}


Response 201 Created:

{
  "id": "generated-uuid-here",
  "title": "New Book",
  "author": "John Smith",
  "isbn": "978-1111111111",
  "publisher": "My Publisher",
  "year": 2024,
  "description": "Created via Thunder Client",
  "archived": false
}


Validation errors return 400 with:

{ "error": "Missing required field: title" }



3. GET /api/books/{book_id}

Description:
Retrieve a single book by ID.

Returns 404 with { "error": "Book not found" } if the ID does not exist.



4. PUT /api/books/{book_id}

Description:
Update an existing book (partial update). Any subset of fields is allowed.

Example request:

{
  "title": "Updated Title",
  "year": 2021
}


Attempts to change "id" are rejected with 400 and {"error": "Cannot change book id"}.



5. DELETE /api/books/{book_id}

Description:
Delete a book.

200 with {"message": "Deleted successfully"} when it exists.

404 with {"error": "Book not found"} otherwise.



6. GET /api/books/count

Description:
Return the number of books.

Response 200:

{ "count": 42 }


Backed by sql_get_book_count() when USE_SQL=True, otherwise len(books).



7. POST /api/books/purge

Description:
Delete all books.

SQL mode: DELETE FROM dbo.Books.

Memory mode: books.clear().

Response 200:

{ "message": "All books removed (deleted 10)" }


Where 10 is the number of rows/items removed.



8. PATCH /api/books/validate

Description:
Batch validation / archival.

Rules:

SQL mode:
Archived = 1 for any book where Year < (currentYear - 10) and not already archived.

Memory mode:
Sets b["archived"] = True for those items.

Response 200:

{
  "updatedCount": 3,
  "timestamp": "2025-12-04T07:30:12.345678Z",
  "mode": "sql"
}


Or "mode": "memory" in local testing.

