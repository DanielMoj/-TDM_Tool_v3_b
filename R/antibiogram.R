
# R/antibiogram.R
read_antibiogram_csv <- function(path) {
  stopifnot(file.exists(path))
  df <- readr::read_csv(path, show_col_types = FALSE, progress = FALSE)
  req_cols <- c("drug","mic","prob")
  miss <- setdiff(req_cols, names(df)); if (length(miss) > 0) stop("Missing columns: ", paste(miss, collapse=", "))
  df$drug <- as.character(df$drug); df$mic <- as.numeric(df$mic); df$prob <- as.numeric(df$prob)
  df <- df[is.finite(df$mic) & is.finite(df$prob) & df$prob >= 0, ]
  df <- dplyr::group_by(df, drug) |> dplyr::mutate(prob = prob / sum(prob)) |> dplyr::ungroup()
  df
}
antibiogram_to_text <- function(df, drug) {
  sub <- df[df$drug == drug, ]; if (nrow(sub) == 0) return("")
  paste(sprintf("%g:%0.3f", sub$mic, sub$prob), collapse = ", ")
}


# ---- DB Bridge ----
antibiogram_import_to_db <- function(path, source = "upload", version = NULL) {
  con <- connect_pg()
  on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  df <- read_antibiogram_csv(path)
  db_import_antibiogram(con, df, source = source, version = version)
}

antibiogram_drugs_db <- function() {
  con <- connect_pg()
  on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  db_list_antibiogram_drugs(con)
}

antibiogram_from_db <- function(drug) {
  con <- connect_pg()
  on.exit(try(DBI::dbDisconnect(con), silent = TRUE))
  db_get_antibiogram(con, drug)
}
