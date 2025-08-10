# R/pk_models.R
suppressPackageStartupMessages({ library(deSolve) })

# analytisch: 1-Kompartiment, IV-Infusion
conc_contrib_one_dose <- function(t, CL, Vc, dose, tinf, t0) {
  k10 <- CL / Vc
  R <- dose / tinf
  dt <- t - t0
  out <- numeric(length(t))
  during <- which(dt > 0 & dt <= tinf)
  if (length(during)) out[during] <- (R / (k10 * Vc)) * (1 - exp(-k10 * dt[during]))
  after  <- which(dt > tinf)
  if (length(after))  out[after]  <- (R / (k10 * Vc)) * (1 - exp(-k10 * tinf)) * exp(-k10 * (dt[after] - tinf))
  out
}

conc_profile_1c <- function(times, CL, Vc, dose, tau, tinf, n_doses, start_time=0) {
  conc <- numeric(length(times))
  for (i in 0:(n_doses-1)) {
    t0 <- start_time + i * tau
    conc <- conc + conc_contrib_one_dose(times, CL, Vc, dose, tinf, t0)
  }
  conc
}

# ODEs für 2C/3C, Infusionsrate als forcings
ode_rhs <- function(t, A, pars) {
  with(as.list(pars), {
    # Infusionsrate (mg/h) aktiv, wenn innerhalb eines Infusionsfensters
    rate <- 0
    if (nrow(doses) > 0) {
      for (i in 1:nrow(doses)) {
        t0 <- doses$t0[i]; tinf <- doses$tinf[i]; R <- doses$rate[i]
        if (t > t0 && t <= t0 + tinf) rate <- rate + R
      }
    }
    dA1 <- rate - (k10 + k12 + k13) * A[1] + k21 * A[2] + k31 * A[3]
    dA2 <- k12 * A[1] - k21 * A[2]
    dA3 <- k13 * A[1] - k31 * A[3]
    list(c(dA1, dA2, dA3))
  })
}

conc_profile_multi <- function(times, theta, regimen, model_type = "2C") {
  CL <- theta[["CL"]]; Vc <- theta[["Vc"]]
  Q1 <- theta[["Q1"]] %||% 0; Vp1 <- theta[["Vp1"]] %||% 1
  Q2 <- theta[["Q2"]] %||% 0; Vp2 <- theta[["Vp2"]] %||% 1
  k10 <- CL / Vc
  k12 <- ifelse(model_type %in% c("2C","3C"), Q1/Vc, 0)
  k21 <- ifelse(model_type %in% c("2C","3C"), Q1/Vp1, 0)
  k13 <- ifelse(model_type == "3C", Q2/Vc, 0)
  k31 <- ifelse(model_type == "3C", Q2/Vp2, 0)
  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  A0 <- c(0,0,0)
  pars <- list(k10=k10,k12=k12,k21=k21,k13=k13,k31=k31,doses=doses)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = ode_rhs, parms = pars, method = "lsoda")
  df <- as.data.frame(sol)
  conc <- approx(df$time, df$A.1 / Vc, xout = times)$y
  conc
}

# Kovariatenmodell (einfaches Beispiel)
# Allometrie + CrCL-Effekt auf CL
apply_covariates <- function(theta_base, covariates, drug) {
  wt <- covariates$weight %||% 70
  crcl <- covariates$crcl
  # Allometrische Skalierung
  theta <- theta_base
  if (!is.null(theta[["CL"]])) theta[["CL"]] <- theta[["CL"]] * (wt/70)^0.75
  if (!is.null(theta[["Vc"]])) theta[["Vc"]] <- theta[["Vc"]] * (wt/70)^1.0
  # CrCL (falls vorhanden), einfacher linearer Effekt (Platzhalter)
  if (!is.null(crcl) && is.finite(crcl) && !is.na(crcl) && !is.null(theta[["CL"]])) {
    theta[["CL"]] <- theta[["CL"]] * (crcl / 100)
  }
  theta
}

predict_conc_grid <- function(times, regimen, theta, model_type) {
  if (model_type == "MM") {
    return(conc_profile_mm_1c(times, theta, regimen))
  }
  if (model_type == "TMDD") {
    return(conc_profile_tmdd_1c_qss(times, theta, regimen))
  }
  if (model_type == "2C_CRRT" || model_type == "3C_CRRT") {
    # expects theta$CL as baseline, plus optional theta$kappa for CRRT contribution
    kappa <- theta[["kappa"]] %||% 1.0
    CL_base <- theta[["CL"]]
    sc <- getOption("crrt_schedule_df", default = data.frame())
    CLf <- function(t) { CL_base + cl_crrt_fun(sc, kappa)(t) }
    return(conc_profile_multi_tvcl(times, theta, regimen, ifelse(model_type=="2C_CRRT","2C","3C"), CL_fun = CLf))
  }

  if (model_type == "1C") {
    conc_profile_1c(times, CL = theta[["CL"]], Vc = theta[["Vc"]],
                    dose = regimen$dose, tau = regimen$tau, tinf = regimen$tinf,
                    n_doses = regimen$n_doses, start_time = regimen$start_time)
  } else {
    conc_profile_multi(times, theta, regimen, model_type)
  }
}

# Dosisvorschlag über Simulation der Steady-State-Talspiegel
ss_trough <- function(dose, tau, tinf, theta, model_type) {
  reg <- list(dose = dose, tau = tau, tinf = tinf, n_doses = 20L, start_time = 0)
  t_trough <- reg$n_doses * tau - 1e-3
  times <- seq(0, reg$n_doses * tau, by = 0.05)
  c <- predict_conc_grid(times, reg, theta, model_type)
  approx(times, c, xout = t_trough)$y
}

propose_dose_for_target_adv <- function(target_trough, tau, tinf, theta, model_type, bounds = c(50, 8000)) {
  f <- function(dose) ss_trough(dose, tau, tinf, theta, model_type) - target_trough
  fl <- f(bounds[1]); fu <- f(bounds[2])
  if (!is.finite(fl) || !is.finite(fu)) return(list(dose_mg = NA_real_))
  if (fl >= 0) return(list(dose_mg = bounds[1]))
  if (fu <= 0) return(list(dose_mg = NA_real_))
  uniroot(f, lower = bounds[1], upper = bounds[2]) |> (\(z) list(dose_mg = z$root))()
}


# ODE with time-varying clearance via function CL_fun(t)
conc_profile_multi_tvcl <- function(times, theta, regimen, model_type = "2C", CL_fun = NULL) {
  Vc <- theta[["Vc"]]; Q1 <- theta[["Q1"]] %||% 0; Vp1 <- theta[["Vp1"]] %||% 1
  Q2 <- theta[["Q2"]] %||% 0; Vp2 <- theta[["Vp2"]] %||% 1
  k12 <- ifelse(model_type %in% c("2C","3C"), Q1/Vc, 0)
  k21 <- ifelse(model_type %in% c("2C","3C"), Q1/Vp1, 0)
  k13 <- ifelse(model_type == "3C", Q2/Vc, 0)
  k31 <- ifelse(model_type == "3C", Q2/Vp2, 0)

  doses <- data.frame(
    t0 = regimen$start_time + (0:(regimen$n_doses-1)) * regimen$tau,
    tinf = regimen$tinf,
    rate = regimen$dose / regimen$tinf
  )
  rhs <- function(t, A, pars) {
    rate <- 0
    if (nrow(doses) > 0) for (i in 1:nrow(doses)) {
      if (t > doses$t0[i] && t <= doses$t0[i] + doses$tinf[i]) rate <- rate + doses$rate[i]
    }
    CLt <- if (!is.null(CL_fun)) CL_fun(t) else theta[["CL"]]
    k10 <- CLt / Vc
    dA1 <- rate - (k10 + k12 + k13) * A[1] + k21 * A[2] + k31 * A[3]
    dA2 <- k12 * A[1] - k21 * A[2]
    dA3 <- k13 * A[1] - k31 * A[3]
    list(c(dA1, dA2, dA3))
  }
  A0 <- c(0,0,0)
  sol <- deSolve::ode(y = A0, times = sort(unique(c(0, times))), func = rhs, parms = NULL, method = "lsoda")
  df <- as.data.frame(sol)
  approx(df$time, df$A.1 / Vc, xout = times)$y
}
