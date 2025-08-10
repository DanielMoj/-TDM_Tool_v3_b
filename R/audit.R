# R/audit.R
# SECURITY: Using HMAC for audit chain integrity instead of simple hashing

ensure_audit_file <- function(path) {
  if (!file.exists(path)) {
    dir.create(dirname(path), showWarnings = FALSE, recursive = TRUE)
    readr::write_csv(tibble::tibble(
      timestamp = character(), user = character(), role = character(),
      event = character(), details = character()
    ), path)
  }
}

log_event <- function(path, user_info, event, details = list()) {
  ensure_audit_file(path)
  u <- tryCatch(if (is.function(user_info$user)) user_info$user() else user_info$user, error = function(e) NULL)
  r <- tryCatch(if (is.function(user_info$role)) user_info$role() else user_info$role, error = function(e) NULL)
  df <- tibble::tibble(
    timestamp = as.character(Sys.time()),
    user = u %||% "guest",
    role = r %||% "guest",
    event = event,
    details = jsonlite::toJSON(details, auto_unbox = TRUE)
  )
  readr::write_csv(df, path, append = TRUE)
}

# --- Hash-chained Audit Log with HMAC ---
# SECURITY: Fixed - Now uses HMAC for integrity protection
audit_append_hashchain <- function(file = "log/audit.csv", actor, action, payload = list()) {
  if (!requireNamespace("digest", quietly = TRUE)) stop("Bitte Paket 'digest' installieren.")
  
  # SECURITY: Get HMAC key from environment
  hmac_key <- Sys.getenv("AUDIT_HMAC_KEY", "")
  if (!nzchar(hmac_key)) {
    warning("AUDIT_HMAC_KEY not set - using default (INSECURE for production)")
    hmac_key <- "DEFAULT_HMAC_KEY_CHANGE_ME"
  }
  
  dir.create(dirname(file), showWarnings = FALSE, recursive = TRUE)
  prev_hash <- "GENESIS"
  if (file.exists(file)) {
    tb <- try(readr::read_csv(file, show_col_types = FALSE, progress = FALSE), silent = TRUE)
    if (!inherits(tb, "try-error") && nrow(tb) > 0) prev_hash <- tail(tb$hash, 1)
  }
  ts <- format(Sys.time(), tz = "UTC", usetz = TRUE)
  payload_json <- jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null")
  chain_input <- paste(prev_hash, ts, actor, action, payload_json, sep = "|")
  
  # SECURITY: Use HMAC instead of simple hash
  h <- digest::hmac(key = hmac_key, object = chain_input, algo = "sha256")
  
  df <- data.frame(ts = ts, actor = actor, action = action, payload = payload_json, prev_hash = prev_hash, hash = h)
  readr::write_csv(df, file, append = file.exists(file))
  invisible(h)
}

# SECURITY: Fixed - Now verifies HMAC chain
audit_verify_chain <- function(file = "log/audit.csv") {
  if (!requireNamespace("digest", quietly = TRUE)) stop("Bitte Paket 'digest' installieren.")
  if (!file.exists(file)) return(TRUE)
  
  # SECURITY: Get HMAC key from environment
  hmac_key <- Sys.getenv("AUDIT_HMAC_KEY", "")
  if (!nzchar(hmac_key)) {
    warning("AUDIT_HMAC_KEY not set - using default (INSECURE for production)")
    hmac_key <- "DEFAULT_HMAC_KEY_CHANGE_ME"
  }
  
  tb <- readr::read_csv(file, show_col_types = FALSE, progress = FALSE)
  if (nrow(tb) == 0) return(TRUE)
  prev_hash <- "GENESIS"
  for (i in 1:nrow(tb)) {
    row <- tb[i,]
    chain_input <- paste(prev_hash, row$ts, row$actor, row$action, row$payload, sep = "|")
    # SECURITY: Verify using HMAC
    expected <- digest::hmac(key = hmac_key, object = chain_input, algo = "sha256")
    if (row$hash != expected) {
      warning(sprintf("Chain broken at row %d", i))
      return(FALSE)
    }
    prev_hash <- row$hash
  }
  TRUE
}

# --- Central audit event function ---
audit_event <- function(action, payload = list(), session = NULL, require_reason = FALSE) {
  if (require_reason && (is.null(payload$reason) || !nzchar(payload$reason))) {
    stop("Diese Aktion erfordert eine Begründung")
  }
  actor <- if (!is.null(session)) {
    tryCatch(session$userData$user(), error = function(e) "guest")
  } else {
    .audit_do_append(actor, action, payload)
  }
}

# SECURITY: Fixed - DB write also uses HMAC for integrity
.aud_db_write <- function(entry) {
  # Optional DB sink
  if (!requireNamespace("DBI", quietly = TRUE) || !requireNamespace("RPostgres", quietly = TRUE)) return(invisible(FALSE))
  dsn_ok <- nzchar(Sys.getenv("PGDATABASE",""))
  if (!dsn_ok) return(invisible(FALSE))
  con <- try(connect_pg(), silent = TRUE); if (inherits(con, "try-error")) return(invisible(FALSE))
  on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  
  # SECURITY: Fixed - Using parameterized query to get previous hash
  prev <- try(DBI::dbGetQuery(con, "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1"), silent = TRUE)
  prev_hash <- if (!inherits(prev, "try-error") && nrow(prev) > 0) prev$hash[1] else "GENESIS"
  
  # SECURITY: Get HMAC key from environment
  hmac_key <- Sys.getenv("AUDIT_HMAC_KEY", "")
  if (!nzchar(hmac_key)) {
    warning("AUDIT_HMAC_KEY not set - using default (INSECURE for production)")
    hmac_key <- "DEFAULT_HMAC_KEY_CHANGE_ME"
  }
  
  ts <- format(Sys.time(), tz = "UTC", usetz = TRUE)
  payload_json <- jsonlite::toJSON(entry$payload, auto_unbox = TRUE, null = "null")
  chain_input <- paste(prev_hash, ts, entry$actor, entry$action, payload_json, sep = "|")
  
  # SECURITY: Use HMAC instead of simple hash
  h <- digest::hmac(key = hmac_key, object = chain_input, algo = "sha256")
  
  # SECURITY: Fixed - Using parameterized query
  sql <- "INSERT INTO audit_log(ts, actor, action, payload, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6)"
  DBI::dbExecute(con, sql, params = list(ts, entry$actor, entry$action, payload_json, prev_hash, h))
  invisible(TRUE)
}

.audit_do_append <- function(actor, action, payload) {
  entry <- list(actor = actor, action = action, payload = payload)
  try(audit_append_hashchain(actor = actor, action = action, payload = payload), silent = TRUE)
  try(.aud_db_write(entry), silent = TRUE)
  invisible(TRUE)
}

# Helper function
`%||%` <- function(a, b) if (is.null(a) || is.na(a) || (is.character(a) && !nzchar(a))) b else a

# Required for DB connection
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