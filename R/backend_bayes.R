# R/backend_bayes.R
# Backends: Laplace (optim), Stan (cmdstanr/rstan), JAGS (rjags)
suppressPackageStartupMessages({
  library(numDeriv)
})

backend_status <- function() {
  has_cmdstan <- requireNamespace("cmdstanr", quietly = TRUE)
  has_rstan   <- requireNamespace("rstan", quietly = TRUE)
  has_rjags   <- requireNamespace("rjags", quietly = TRUE)
  glue::glue("cmdstanr: {has_cmdstan}, rstan: {has_rstan}, rjags: {has_rjags}")
}

# Prior-Parsing: erwartet priors$theta_log (mu/sd auf log-Skala)
draw_from_priors <- function(priors) {
  th <- priors$theta
  exp(setNames(rnorm(length(th), priors$theta_log$mu[names(th)], priors$theta_log$sd[names(th)]), names(th)))
}

neg_log_post_map <- function(par_log, obs, regimen, priors, model_type, error_model, sigma_add, sigma_prop, covariates, blq_lloq = NA_real_, is_blq = NULL, creatinine_data = NULL) {
  # Parameter auf natürlicher Skala
  th_names <- names(priors$theta)
  th <- exp(setNames(par_log, th_names))
  th <- apply_covariates(th, covariates, priors$name)
  # Vorhersage
  pred <- predict_conc_grid(obs$time, regimen, th, model_type)
  # Fehler
  sigfun <- make_sigma_fun(error_model, sigma_add, sigma_prop)
  sig <- sigfun(pred)
  ll <- loglik_residuals_vec(obs$conc, pred, error_model, sigma_add, sigma_prop, lloq = blq_lloq, is_blq = is_blq)
  # joint-like penalty linking CL to creatinine-derived expectation
  ll <- ll + tryCatch(cl_creatinine_penalty(exp(par_log[["logCL"]]), covariates$age %||% 60, covariates$weight %||% 70, covariates$sex %||% "male", creatinine_data), error = function(e) 0)
  # Priors (lognormal)
  lp <- sum(dnorm(par_log, mean = priors$theta_log$mu[th_names], sd = priors$theta_log$sd[th_names], log = TRUE))
  -(ll + lp)
}

run_fit_laplace <- function(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  validate_inputs_units(regimen, obs)
  th0 <- log(priors$theta) # Start bei prior-Mean
  sigma_add <- sigma_init[["add"]]; sigma_prop <- sigma_init[["prop"]]
  obj <- function(p) neg_log_post_map(p, obs, regimen, priors, model_type, error_model, sigma_add, sigma_prop, covariates, blq_lloq, is_blq, creatinine_data)
  opt <- optim(th0, obj, method = "BFGS", hessian = TRUE, control = list(maxit = 1000))
  cov <- tryCatch(solve(opt$hessian), error = function(e) diag(rep(0.05^2, length(th0))))
  draws <- MASS::mvrnorm(n = 800, mu = opt$par, Sigma = cov)
  draws_nat <- exp(draws)
  colnames(draws_nat) <- names(priors$theta)
  list(draws = draws_nat)
}


run_fit_stan <- function(obs, regimen, priors, model_type, error_model, covariates,
                         estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  # --- HMC Controls (from options or defaults) ---
  .hmc <- getOption("tdmx_hmc", default = list(
    chains = 4L, iter_warmup = 1000L, iter_sampling = 1000L,
    parallel_chains = NULL, adapt_delta = 0.9, max_treedepth = 12L, seed = 1234L
  ))

  if (!requireNamespace("cmdstanr", quietly = TRUE)) {
    warning("cmdstanr nicht verfügbar, fallback auf Laplace.")
    return(run_fit_laplace(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq))
  }
  stan_file <- stan_file_for_model(model_type)
  data_list <- stan_data_list2(obs, regimen, priors, model_type, error_model, estimate_sigma, sigma_init, blq_lloq, is_blq)
  mod <- cmdstanr::cmdstan_model(stan_file)
  fit <- mod$sample(
    data = data_list,
    seed = .hmc$seed,
    chains = .hmc$chains,
    parallel_chains = if (is.null(.hmc$parallel_chains)) .hmc$chains else .hmc$parallel_chains,
    iter_warmup = .hmc$iter_warmup,
    iter_sampling = .hmc$iter_sampling,
    adapt_delta = .hmc$adapt_delta,
    max_treedepth = .hmc$max_treedepth
  )
  draws <- as.data.frame(fit$draws(variables = c("CL_out","Vc_out","Q1_out","Vp1_out","Q2_out","Vp2_out","sigma_add","sigma_prop","nu"), format = "df"))
  # rename outputs to expected names
  names(draws) <- sub("_out$", "", names(draws))
  diagnostics <- NULL
  try({
    if (requireNamespace("posterior", quietly = TRUE)) {
      summ <- posterior::summarise_draws(fit$draws())
      keep <- intersect(c("CL_out","Vc_out","Q1_out","Vp1_out","Q2_out","Vp2_out","sigma_add","sigma_prop","nu"), summ$variable)
      summ <- summ[summ$variable %in% keep, c("variable","rhat","ess_bulk","ess_tail"), drop = FALSE]
    } else { summ <- NULL }
    sdiag <- try(fit$diagnostic_summary(), silent = TRUE)
    div <- try(sdiag$num_divergent[1], silent = TRUE)
    treedepth <- try(sdiag$num_max_treedepth[1], silent = TRUE)
    stepsize <- try(as.numeric(fit$metadata()$step_size_adaptation), silent = TRUE)
    diagnostics <- list(summary = summ, divergences = div, treedepth_hits = treedepth, stepsize = stepsize)
  }, silent = TRUE)
  list(draws = draws, diagnostics = diagnostics)
}


# FIX: removed stray call below; this was causing syntax error in parsing
# stan_data_list2(obs, regimen, priors, model_type, error_model, estimate_sigma, sigma_init, blq_lloq, is_blq)
  # legacy below kept for reference
  # data <- list(
    N = nrow(obs),
    t_obs = obs$time,
    y = obs$conc,
    n_cmt = switch(model_type, "1C"=1L, "2C"=2L, "3C"=3L),
    n_inf = regimen$n_doses,
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = rep(regimen$tinf, regimen$n_doses),
    rate = rep(regimen$dose / regimen$tinf, regimen$n_doses),
    K = length(priors$theta_log$mu),
    mu = as.numeric(priors$theta_log$mu),
    sd = as.numeric(pmax(1e-6, priors$theta_log$sd)),
    idx_CL = which(names(priors$theta)=="CL"),
    idx_Vc = which(names(priors$theta)=="Vc"),
    idx_Q1 = which(names(priors$theta)=="Q1"),
    idx_Vp1 = which(names(priors$theta)=="Vp1"),
    idx_Q2 = which(names(priors$theta)=="Q2"),
    idx_Vp2 = which(names(priors$theta)=="Vp2"),
    error_model = switch(error_model, "additiv"=1L, "proportional"=2L, "kombiniert"=3L),
    est_sigma = ifelse(estimate_sigma, 1L, 0L),
    sigma_add_init = sigma_init[["add"]],
    sigma_prop_init = sigma_init[["prop"]]
  )
  # Fill missing indexes
  for (k in c("idx_Q1","idx_Vp1","idx_Q2","idx_Vp2")) if (length(data[[k]])==0) data[[k]] <- 0L

  if (requireNamespace("cmdstanr", quietly = TRUE)) {
    mod <- cmdstanr::cmdstan_model(stan_file)
    fit <- mod$sample(data = data, chains = 4, parallel_chains = 4, iter_warmup = 500, iter_sampling = 1000, refresh = 0)
    dr <- as.data.frame(fit$draws(variables = c("CL","Vc","Q1","Vp1","Q2","Vp2"), format = "df"))
    diag <- tryCatch(as.data.frame(fit$summary(variables = c("CL","Vc","Q1","Vp1","Q2","Vp2"))), error = function(e) NULL)
  } else {
    stan_text <- readChar(stan_file, file.info(stan_file)$size)
    sm <- rstan::stan_model(model_code = stan_text)
    fit <- rstan::sampling(sm, data = data, chains = 4, iter = 1500, warmup = 500, refresh = 0)
    dr <- as.data.frame(rstan::extract(fit, pars = c("CL","Vc","Q1","Vp1","Q2","Vp2")))
    diag <- tryCatch(as.data.frame(summary(fit)$summary), error = function(e) NULL)
  }
  # Clean draws
  keep <- intersect(colnames(dr), names(priors$theta))
  dr <- dr[, keep, drop = FALSE]
  list(draws = dr, diagnostics = diag)
}


run_fit_stan_advi <- function(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  if (!requireNamespace("cmdstanr", quietly = TRUE) && !requireNamespace("rstan", quietly = TRUE)) {
    warning("Stan-ADVI nicht verfügbar, fallback auf Laplace.")
    return(run_fit_laplace(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq))
  }
  stan_file <- stan_file_for_model(model_type)
  data <- stan_data_list2(obs, regimen, priors, model_type, error_model, estimate_sigma, sigma_init, blq_lloq, is_blq)
  if (requireNamespace("cmdstanr", quietly = TRUE)) {
    mod <- cmdstanr::cmdstan_model(stan_file)
    fit <- mod$variational(data = data, output_samples = 1000, seed = 123)
    dr <- as.data.frame(fit$draws(variables = c("CL","Vc","Q1","Vp1","Q2","Vp2"), format = "df"))
  } else {
    stan_text <- readChar(stan_file, file.info(stan_file)$size)
    sm <- rstan::stan_model(model_code = stan_text)
    fit <- rstan::vb(sm, data = data, output_samples = 1000, seed = 123)
    dr <- as.data.frame(rstan::extract(fit, pars = c("CL","Vc","Q1","Vp1","Q2","Vp2")))
  }
  keep <- intersect(colnames(dr), names(priors$theta))
  dr <- dr[, keep, drop = FALSE]
  list(draws = dr, diagnostics = NULL)
}




run_fit_jags <- function(obs, regimen, priors, model_type, error_model, covariates,
                         estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  if (!requireNamespace("rjags", quietly = TRUE)) stop("rjags nicht installiert")
  # Data prep
  obs_times <- obs$time; y <- obs$conc
  is_blq <- if (is.null(is_blq)) as.integer(is.na(y)) else as.integer(is_blq)
  y_obs <- ifelse(is.na(y), 0.0, y)
  lloq <- ifelse(is.na(y), blq_lloq, blq_lloq)  # constant lloq for all (if provided)
  grid <- build_time_grid_adaptive(regimen, obs_times, dt_min = 0.025, dt_base = 0.25, refine_window = 0.5)
  # Initial concentration
  C0 <- 0.0
  # Select JAGS model file
  jags_file <- switch(model_type,
    "MM-1C" = "models/jags/pk_mm_onecpt_disc.jags",
    "TMDD-QSS-1C" = "models/jags/pk_tmdd_qss_onecpt_disc.jags",
    # Fallback to linear 1C infusion model if exists
    "1C" = "models/jags/pk_onecpt_inf.jags",
    "models/jags/pk_onecpt_inf.jags"
  )
  data_list <- list(
    N = length(y_obs),
    y = y_obs,
    is_blq = is_blq,
    lloq = rep(blq_lloq, length(y_obs)),
    NT = length(grid$t),
    dt = grid$dt,
    rate = grid$rate,
    idx = grid$idx,
    C0 = C0
  )
  # Inits (log-scale priors)
  inits <- function() {
    lst <- list(
      logCL = log(priors$theta$CL %||% 5),
      logVc = log(priors$theta$Vc %||% 30),
      sigma = sigma_init %||% 2
    )
    if (model_type == "MM-1C") {
      lst$logVmax <- log(priors$theta$Vmax %||% 500)
      lst$logKm <- log(priors$theta$Km %||% 10)
    }
    if (model_type == "TMDD-QSS-1C") {
      lst$logKint <- log(priors$theta$kint %||% 0.1)
      lst$logRtot <- log(priors$theta$Rtot %||% 50)
      lst$logKss <- log(priors$theta$Kss %||% 10)
    }
    lst
  }
  # Parameters to monitor
  params <- c("CL","Vc","sigma")
  if (model_type == "MM-1C") params <- c(params, "Vmax","Km")
  if (model_type == "TMDD-QSS-1C") params <- c(params, "kint","Rtot","Kss")
  j <- rjags::jags.model(jags_file, data = data_list, inits = inits, n.chains = 3, quiet = TRUE)
  rjags::update(j, n.iter = 1000, progress.bar = "none")
  m <- rjags::coda.samples(j, variable.names = params, n.iter = 2000, thin = 2, progress.bar = "none")
  dr <- as.data.frame(do.call(rbind, m))
  names(dr) <- gsub("^\.", "", names(dr))
  list(draws = dr, diagnostics = NULL)
}





run_fit <- function(obs, regimen, priors, model_type, error_model, covariates, backend, estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL, use_cache = TRUE, creatinine_data = NULL) {
  backend <- sub(" .*","", backend) # "Laplace", "Stan", "JAGS"
  # cache key
  key <- cache_key_for_fit(obs, regimen, priors, model_type, error_model, covariates, backend, estimate_sigma, sigma_init)
  if (use_cache) {
    cval <- cache_get(key)
    if (!is.null(cval)) return(cval)
  }
  # adjust priors for covariates (pediatric & weight)
  pri_adj <- tryCatch(adjust_priors_for_covariates(priors, covariates), error = function(e) priors)
  priors <- pri_adj
  res <- switch(backend,
    "Laplace" = run_fit_laplace(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq),
    "Stan"    = run_fit_stan(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq),
    "JAGS"    = run_fit_jags2(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq),
    "Stan-ADVI" = run_fit_stan_advi(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq),
    "Stan-Pathfinder" = run_fit_stan_pathfinder(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq),
    run_fit_laplace(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init)
  )
  draws <- as.data.frame(res$draws)
  # Posterior-Zusammenfassung
  summ <- lapply(draws, function(x) c(median = stats::median(x), q2.5 = quantile(x, 0.025), q97.5 = quantile(x, 0.975)))
  median <- sapply(summ, function(z) z["median"])
  q2.5 <- sapply(summ, function(z) z["q2.5"])
  q97.5 <- sapply(summ, function(z) z["q97.5"])
  out <- list(draws = draws, posterior_summary = list(median = median, q2.5 = q2.5, q97.5 = q97.5), diagnostics = res$diagnostics %||% NULL)
  if (use_cache) cache_put(key, out)
  out
}


# --- ADVI / Variational path (requires cmdstanr) ---
fit_advi <- function(data_list, stan_file, seed = 1234, iter = 20000, output_samples = 1000, cache_key = NULL) {
  if (!requireNamespace("cmdstanr", quietly = TRUE)) stop("cmdstanr nicht installiert")
  if (!file.exists(stan_file)) stop("Stan file fehlt: ", stan_file)
  cache_file <- if (!is.null(cache_key)) file.path("cache", paste0("advi_", gsub("[^A-Za-z0-9_]+","_", cache_key), ".rds")) else NULL
  if (!is.null(cache_file) && file.exists(cache_file)) {
    res <- readRDS(cache_file); return(res)
  }
  mod <- cmdstanr::cmdstan_model(stan_file)
  fit <- mod$variational(data = data_list, seed = seed, iter = iter, output_samples = output_samples)
  draws <- as.data.frame(fit$draws())
  diagnostics <- NULL
  try({
    if (requireNamespace("posterior", quietly = TRUE)) {
      summ <- posterior::summarise_draws(fit$draws())
      # Keep key PK params if exist
      keep <- intersect(c("CL","Vc","Q1","Vp1","Q2","Vp2","sigma","nu"), summ$variable)
      summ <- summ[summ$variable %in% keep, c("variable","rhat","ess_bulk","ess_tail"), drop = FALSE]
    } else { summ <- NULL }
    # Sampler diagnostics
    sdiag <- try(fit$diagnostic_summary(), silent = TRUE)
    div <- try(fit$diagnostic_summary()$num_divergent[1], silent = TRUE)
    treedepth <- try(fit$diagnostic_summary()$num_max_treedepth[1], silent = TRUE)
    stepsize <- try(as.numeric(fit$metadata()$step_size_adaptation), silent = TRUE)
    diagnostics <- list(summary = summ, divergences = div, treedepth_hits = treedepth, stepsize = stepsize)
  }, silent = TRUE)
  res <- list(draws = draws, method = "advi", seed = seed)
  dir.create("cache", showWarnings = FALSE)
  if (!is.null(cache_file)) saveRDS(res, cache_file)
  res
}


run_fit_stan_pathfinder <- function(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  if (!requireNamespace("cmdstanr", quietly = TRUE)) {
    warning("cmdstanr nicht verfügbar, fallback auf ADVI.")
    return(run_fit_stan_advi(obs, regimen, priors, model_type, error_model, covariates, estimate_sigma, sigma_init, blq_lloq, is_blq))
  }
  stan_file <- stan_file_for_model(model_type)
  data <- stan_data_list2(obs, regimen, priors, model_type, error_model, estimate_sigma, sigma_init, blq_lloq, is_blq)
  mod <- cmdstanr::cmdstan_model(stan_file)
  pf <- mod$pathfinder(data = data, draws = 1000, psis_resamples = 1000, seed = 1234)
  dr <- as.data.frame(pf$draws(variables = c("CL","Vc","Q1","Vp1","Q2","Vp2"), format = "df"))
  keep <- intersect(colnames(dr), names(priors$theta))
  dr <- dr[, keep, drop = FALSE]
  list(draws = dr, diagnostics = NULL)
}


stan_file_for_model <- function(model_type) {
  # Map UI model_type to Stan file
  if (model_type %in% c("1C","2C","3C")) return("models/stan/pk_multicpt_ode.stan")
  if (identical(model_type, "MM-1C")) return("models/stan/pk_mm_onecpt_ode.stan")
  if (identical(model_type, "TMDD-QSS-1C")) return("models/stan/pk_tmdd_qss_onecpt_ode.stan")
  "models/stan/pk_multicpt_ode.stan"
}

# Build infusion schedule from regimen
make_infusion_schedule <- function(regimen) {
  # regimen: list(dose, tau, tinf, n_doses, start=0)
  n <- as.integer(regimen$n_doses %||% 1)
  t0 <- seq(from = regimen$start %||% 0, by = regimen$tau, length.out = n)
  tinf <- rep(regimen$tinf, n)
  rate <- rep(regimen$dose / max(1e-6, regimen$tinf), n)
  list(n_inf = n, t0 = t0, tinf = tinf, rate = rate)
}

# Build priors vector for arbitrary parameter names on log-scale
build_theta_priors <- function(priors, names_needed) {
  mu <- c(); sd <- c()
  for (nm in names_needed) {
    if (!is.null(priors$theta_log$mu[[nm]]) && !is.null(priors$theta_log$sd[[nm]])) {
      mu <- c(mu, priors$theta_log$mu[[nm]])
      sd <- c(sd, pmax(1e-6, priors$theta_log$sd[[nm]]))
    } else {
      # fallback weakly-informative
      def <- switch(nm,
        "CL"   = list(mu = log(5),  sd = 1.0),
        "Vc"   = list(mu = log(30), sd = 1.0),
        "Q1"   = list(mu = log(10), sd = 1.2),
        "Vp1"  = list(mu = log(20), sd = 1.2),
        "Q2"   = list(mu = log(5),  sd = 1.2),
        "Vp2"  = list(mu = log(10), sd = 1.2),
        "Vmax" = list(mu = log(100), sd = 1.5),
        "Km"   = list(mu = log(10),  sd = 1.0),
        "kint" = list(mu = log(0.5), sd = 1.0),
        "Rtot" = list(mu = log(50),  sd = 1.0),
        "Kss"  = list(mu = log(10),  sd = 1.0),
        list(mu = 0, sd = 1.5)
      )
      mu <- c(mu, def$mu); sd <- c(sd, def$sd)
    }
  }
  list(mu = mu, sd = sd)
}




run_fit_jags2 <- function(obs, regimen, priors, model_type, error_model, covariates,
                          estimate_sigma, sigma_init, blq_lloq = NA_real_, is_blq = NULL) {
  if (!requireNamespace("rjags", quietly = TRUE)) stop("rjags nicht installiert")
  obs_times <- obs$time; y <- obs$conc
  is_blq <- as.integer(if (is.null(is_blq)) is.na(y) else is_blq)
  # y as data with NA for censored
  y_dat <- y
  lloq_vec <- rep(blq_lloq %||% 0, length(y))
  grid <- build_time_grid_adaptive(regimen, obs_times, dt_min = 0.025, dt_base = 0.25, refine_window = 0.5)
  Nt <- length(grid$t)
  # base data
  data <- list(
    N = as.integer(length(y_dat)),
    y = as.numeric(y_dat),
    lloq = as.numeric(lloq_vec),
    idx = as.integer(grid$idx),
    Nt = as.integer(Nt),
    dt = as.numeric(grid$dt),
    rate = as.numeric(grid$rate),
    C0 = 0.0,
    error_model = as.integer(error_model %||% 3L),
    est_sigma = as.integer(estimate_sigma %||% 1L),
    sigma_init = as.numeric(sigma_init[["add"]] %||% 1.0),
    sigma_prop = as.numeric(sigma_init[["prop"]] %||% 0.2),
    pi_mix_alpha = 1.0, pi_mix_beta = 1.0,
    # prior hyperparameters (log-scale) defaults; will be overwritten when available
    mu_logCL = 0.0, tau_logCL = 1.0E-2,
    mu_logVc = 0.0, tau_logVc = 1.0E-2
  )
  # model-specific prior hyperparameters
  if (identical(model_type, "MM-1C")) {
    data$mu_logVmax <- 0.0; data$tau_logVmax <- 1.0E-2
    data$mu_logKm   <- 0.0; data$tau_logKm   <- 1.0E-2
    jags_file <- "models/jags/pk_mm_onecpt_disc.jags"
  } else if (identical(model_type, "TMDD-QSS-1C")) {
    data$mu_logKint <- 0.0; data$tau_logKint <- 1.0E-2
    data$mu_logRtot <- 0.0; data$tau_logRtot <- 1.0E-2
    data$mu_logKss  <- 0.0; data$tau_logKss  <- 1.0E-2
    jags_file <- "models/jags/pk_tmdd_qss_onecpt_disc.jags"
  } else {
    stop("JAGS: unbekanntes model_type: ", model_type)
  }
  # priors from JSON (if available)
  if (!is.null(priors) && !is.null(priors$theta_log)) {
    get_mu <- function(name) as.numeric(priors$theta_log$mu[[name]] %||% NA_real_)
    get_sd <- function(name) as.numeric(priors$theta_log$sd[[name]] %||% NA_real_)
    setp <- function(field_mu, field_tau, name) {
      mu <- get_mu(name); sd <- get_sd(name)
      if (!is.na(mu) && !is.na(sd) && sd > 0) {
        data[[field_mu]] <<- mu
        data[[field_tau]] <<- 1 / (sd^2)
      }
    }
    setp("mu_logCL","tau_logCL","CL"); setp("mu_logVc","tau_logVc","Vc")
    if (identical(model_type, "MM-1C")) {
      setp("mu_logVmax","tau_logVmax","Vmax"); setp("mu_logKm","tau_logKm","Km")
    } else if (identical(model_type, "TMDD-QSS-1C")) {
      setp("mu_logKint","tau_logKint","kint"); setp("mu_logRtot","tau_logRtot","Rtot"); setp("mu_logKss","tau_logKss","Kss")
    }
  }
  inits <- function() list(
    logCL = data$mu_logCL, logVc = data$mu_logVc,
    logVmax = if (!is.null(data$mu_logVmax)) data$mu_logVmax else NULL,
    logKm   = if (!is.null(data$mu_logKm))   data$mu_logKm   else NULL,
    logKint = if (!is.null(data$mu_logKint)) data$mu_logKint else NULL,
    logRtot = if (!is.null(data$mu_logRtot)) data$mu_logRtot else NULL,
    logKss  = if (!is.null(data$mu_logKss))  data$mu_logKss  else NULL,
    sigma_add_free = data$sigma_init, sigma_prop = data$sigma_prop, nu = 8,
    pi_mix = 0.05, kappa = 3
  )
  pars <- c("CL","Vc")
  if (identical(model_type,"MM-1C")) pars <- c(pars,"Vmax","Km")
  if (identical(model_type,"TMDD-QSS-1C")) pars <- c(pars,"kint","Rtot","Kss")
  nch <- max(getOption("tdmx_hmc")$chains %||% 2L, 2L)
  jm <- rjags::jags.model(jags_file, data = data, inits = inits, n.chains = nch, quiet = TRUE)
  rjags::update(jm, n.iter = 1000, progress.bar = "none")
  m <- rjags::coda.samples(jm, variable.names = pars, n.iter = 2000, thin = 1, progress.bar = "none")
  draws <- as.data.frame(do.call(rbind, m))
  list(draws = draws, diagnostics = NULL)
}


stan_data_list2 <- function(obs, regimen, priors, model_type, error_model, estimate_sigma, sigma_init, blq_lloq, is_blq) {
  # observations
  N <- nrow(obs)
  t_obs <- as.numeric(obs$time)
  y <- as.numeric(obs$conc)
  is_blq <- as.integer(if (is.null(is_blq)) is.na(y) else is_blq)
  lloq <- as.numeric(blq_lloq %||% 0)
  y[is.na(y)] <- lloq  # value unused when is_blq==1

  # number of compartments
  n_cmt <- switch(model_type,
    "1C" = 1L, "2C" = 2L, "3C" = 3L,
    "MM-1C" = 1L, "TMDD-QSS-1C" = 1L,
    1L
  )

  # infusion schedule
  n_inf <- as.integer(regimen$n_doses %||% 1)
  t0 <- as.numeric((regimen$start_time %||% 0) + (0:(n_inf-1)) * regimen$tau)
  tinf <- rep(as.numeric(regimen$tinf), n_inf)
  rate <- rep(as.numeric(regimen$dose / max(1e-6, regimen$tinf)), n_inf)

  # priors on log-scale
  names_needed <- c("CL","Vc","Q1","Vp1","Q2","Vp2","Vmax","Km","kint","Rtot","Kss")
  pri <- build_theta_priors(priors, names_needed)
  mu <- pri$mu; sd <- pri$sd
  idx <- pri$idx

  list(
    N = as.integer(N),
    t_obs = as.vector(t_obs),
    y = as.vector(y),
    is_blq = as.integer(is_blq),
    lloq = lloq,
    n_cmt = as.integer(n_cmt),
    n_inf = as.integer(n_inf),
    t0 = as.vector(t0),
    tinf = as.vector(tinf),
    rate = as.vector(rate),
    error_model = as.integer(error_model %||% 3L),
    est_sigma = as.integer(estimate_sigma %||% 1L),
    nu = 7,
    mix_w = 0.8,
    mix_scale = 3.0,
    idx_CL = as.integer(idx["CL"] %||% 1L),
    idx_Vc = as.integer(idx["Vc"] %||% 2L),
    idx_Q1 = as.integer(idx["Q1"] %||% 3L),
    idx_Vp1 = as.integer(idx["Vp1"] %||% 4L),
    idx_Q2 = as.integer(idx["Q2"] %||% 5L),
    idx_Vp2 = as.integer(idx["Vp2"] %||% 6L),
    K = as.integer(length(mu)),
    mu = as.vector(mu),
    sd = as.vector(sd),
    sigma_add_init = as.numeric(sigma_init[["add"]] %||% 1.0),
    sigma_prop_init = as.numeric(sigma_init[["prop"]] %||% 0.2)
  )
}
