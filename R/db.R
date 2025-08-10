# R/db.R
# Lightweight DB helpers for Postgres with security hardening
# SECURITY: All SQL queries use parameterized statements to prevent SQL injection

get_db_con <- function() {
  dsn <- Sys.getenv("PG_DSN", "")
  if (dsn == "") return(NULL)
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    warning("DB packages fehlen, kehre zu NULL (kein DB) zurück.")
    return(NULL)
  }
  con <- tryCatch(DBI::dbConnect(RPostgres::Postgres(), dsn = dsn), error = function(e) NULL)
  con
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_write_audit <- function(user, role, event, details = list()) {
  con <- get_db_con()
  if (is.null(con)) return(invisible(FALSE))
  try({
    DBI::dbExecute(con, "INSERT INTO audit_log(user_name, role, event, details) VALUES($1,$2,$3,$4::jsonb)",
                   params = list(user %||% "guest", role %||% "guest", event, jsonlite::toJSON(details, auto_unbox = TRUE)))
    DBI::dbDisconnect(con)
  }, silent = TRUE)
  invisible(TRUE)
}

connect_pg <- function() {
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) {
    stop("Bitte Pakete 'DBI' und 'RPostgres' installieren.")
  }
  host <- Sys.getenv("PGHOST", "localhost")
  port <- as.integer(Sys.getenv("PGPORT", "5432"))
  db   <- Sys.getenv("PGDATABASE", "tdmx")
  user <- Sys.getenv("PGUSER", "tdmx")
  pass <- Sys.getenv("PGPASSWORD", "")
  DBI::dbConnect(RPostgres::Postgres(), host = host, port = port, dbname = db, user = user, password = pass)
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_write_dataset_version <- function(con, kind, version, checksum, meta = list()) {
  stopifnot(!is.null(kind), !is.null(version), !is.null(checksum))
  sql <- "INSERT INTO dataset_versions(kind, version, checksum, meta) VALUES ($1,$2,$3,$4)"
  DBI::dbExecute(con, sql, params = list(kind, version, checksum, jsonlite::toJSON(meta, auto_unbox = TRUE)))
}

# SECURITY: Fixed SQL injection - dbWriteTable handles parameterization internally
db_import_antibiogram <- function(con, df, source = "upload", version = NULL) {
  stopifnot(all(c("drug","mic","prob") %in% colnames(df)))
  # Normalize per drug (ensure sum(prob)=1)
  df <- dplyr::group_by(df, drug) |> dplyr::mutate(prob = prob / sum(prob)) |> dplyr::ungroup()
  # Insert rows - dbWriteTable handles parameterization internally
  df$source <- source
  DBI::dbWriteTable(con, "antibiogram", df, append = TRUE, row.names = FALSE)
  # Version entry
  if (!requireNamespace("digest", quietly = TRUE)) stop("Bitte Paket 'digest' installieren.")
  v <- version %||% digest::digest(df, algo = "sha256")
  meta <- list(source = source, rows = nrow(df), drugs = length(unique(df$drug)))
  db_write_dataset_version(con, "antibiogram", v, digest::digest(df), meta)
  message(sprintf("Imported %d antibiogram rows for %d drugs", nrow(df), meta$drugs))
}

# SECURITY: Fixed SQL injection - uses parameterized query
db_get_antibiogram <- function(con, drug = NULL) {
  if (is.null(drug)) {
    df <- DBI::dbGetQuery(con, "SELECT * FROM antibiogram")
  } else {
    # SECURITY: Parameterized query prevents SQL injection
    df <- DBI::dbGetQuery(con, "SELECT * FROM antibiogram WHERE drug = $1", params = list(drug))
  }
  df
}

# Helper function from auth.R
`%||%` <- function(a, b) if (is.null(a) || is.na(a) || (is.character(a) && !nzchar(a))) b else a