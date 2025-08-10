# R/utils.R
`%||%` <- function(a,b) if (!is.null(a)) a else b

parse_num_list <- function(x) {
  if (is.null(x) || is.na(x) || !nzchar(x)) return(numeric(0))
  as.numeric(trimws(unlist(strsplit(x, ","))))
}

stop_na <- function(x, msg) if (any(!is.finite(x))) stop(msg, call. = FALSE)

rnorm_log <- function(mu, sd, n = 1) exp(rnorm(n, mean = mu, sd = sd))

median_iqr <- function(x) c(median = stats::median(x), IQR = IQR(x))