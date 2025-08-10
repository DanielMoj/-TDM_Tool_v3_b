# app.R
# TDMx-Open Advanced — Demo-Framework mit erweiterten Features
# WICHTIG: Forschungs-/Lehrzwecke. Kein Medizinprodukt. Nicht für klinische Entscheidungen.

suppressPackageStartupMessages({
  library(shiny)
  library(bslib)
  library(ggplot2)
  library(dplyr)
  library(DT)
  library(jsonlite)
  library(glue)
  library(readr)
  library(tibble)
  library(lubridate)
})

source(file.path("R","utils.R"))
source(file.path("R","auth.R"))
source(file.path("R","audit.R"))
source(file.path("R","db.R"))
source(file.path("R","units_checks.R"))
source(file.path("R","prior_db.R"))
source(file.path("R","error_models.R"))
source(file.path("R","pk_models.R"))
source(file.path("R","backend_bayes.R"))
source(file.path("R","optimize_regimen.R"))
source(file.path("R","lis_ingest.R"))
source(file.path("R","antibiogram.R"))
source(file.path("R","ode_grid.R"))
source(file.path("R","loinc.R"))
source(file.path("R","fhir.R"))
source(file.path("R","cache.R"))
source(file.path("R","design.R"))
source(file.path("R","diagnostics.R"))
source(file.path("R","reporting.R"))

app_theme <- bs_theme(version = 5, bootswatch = "flatly")

# ---- Konfiguration ------------------------------------------------------------
config <- list(
  enable_auth = file.exists("config/users.yaml"),
  audit_log_file = "audit/audit_log.csv",
  priors_dir = "priors",
  report_rmd = "report/report.Rmd",
  default_drug = "Meropenem"
)

# ---- UI ----------------------------------------------------------------------
app_ui <- function() {
  page_fluid(
    theme = app_theme,
    tags$head(tags$title("TDMx-Open Advanced")),
    navset_tab(
      id = "tabs",
      nav_panel("TDM Fit",
        layout_sidebar(
          sidebar = sidebar(
            h4("Benutzer"),
            uiOutput("whoami"),
            hr(),
            h4("Wirkstoff & Modell"),
            uiOutput("drug_selector"),
            selectInput("model_type", "Modell", choices = c("1C","2C","3C","MM-1C","TMDD-QSS-1C"), selected = "1C"),
            selectInput("error_model", "Residualfehler", choices = c("additiv","proportional","kombiniert","t-additiv","t-proportional","mixture"), selected = "kombiniert"),
            selectInput("backend", "Bayes-Backend", choices = c("Laplace (schnell)","Stan (voll Bayes)","Stan-ADVI (schnell)","JAGS (voll Bayes)"), 
            conditionalPanel(
              condition = "input.backend && input.backend.indexOf('Stan') >= 0",
              hr(),
              h4("HMC/Stan Einstellungen"),
              numericInput("hmc_chains", "Chains", value = 4, min = 1, step = 1),
              numericInput("hmc_warmup", "Warmup-Iterationen", value = 1000, min = 100, step = 100),
              numericInput("hmc_sampling", "Sampling-Iterationen", value = 1000, min = 100, step = 100),
              numericInput("hmc_adapt_delta", "adapt_delta", value = 0.9, min = 0.5, max = 0.999, step = 0.01),
              numericInput("hmc_max_treedepth", "max_treedepth", value = 12, min = 8, max = 15, step = 1)
            )
selected = "Laplace (schnell)"),
            checkboxInput("use_cache", "Warm-Start/Cache aktivieren", value = TRUE),
            numericInput("stan_chains", "Stan Chains", value = 4, min = 1, step = 1),
            numericInput("stan_iter", "Stan Iter Sampling", value = 1000, min = 200, step = 100),
            hr(),
            h4("Patient & Kovariaten"),
            numericInput("age", "Alter (Jahre)", value = 60, min = 0, step = 1),
            numericInput("weight", "Gewicht (kg)", value = 75, min = 1, step = 0.5),
            numericInput("crcl", "Kreatinin-Clearance (mL/min)", value = NA, min = 0, step = 1),
            hr(),
            h4("Dosierung"),
            selectInput("route", "Applikation", choices = c("IV-Infusion"), selected = "IV-Infusion"),
            numericInput("dose", "Dosis (mg)", value = 1000, min = 1, step = 50),
            numericInput("tau", "Intervall τ (h)", value = 8, min = 0.5, step = 0.5),
            numericInput("tinf", "Infusionsdauer (h)", value = 0.5, min = 0.1, step = 0.1),
            numericInput("n_doses", "Anzahl applizierter Gaben", value = 6, min = 1, step = 1),
            numericInput("start_time", "Startzeit erster Dosis (h)", value = 0, step = 0.5),
            hr(),
            h4("TDM-Messungen"),
            numericInput("lloq", "LLOQ (mg/L) – optional", value = NA, min = 0, step = 0.1),
            checkboxInput("blq_by_lloq", "Werte ≤ LLOQ als BLQ behandeln (M3)", value = FALSE),
            helpText("Zeiten & Konzentrationen als kommagetrennte Listen, z. B. 8, 20 — 12.0, 6.5"),
            textInput("obs_times", "Messzeiten (h)", value = "8, 20"),
            textInput("obs_conc",  "Konzentrationen (mg/L)", value = "12.0, 6.5"),
            checkboxInput("estimate_sigma", "Fehlerparameter schätzen (Bayes)", value = TRUE),
            numericInput("sigma_add_init", "Startwert σ_add (mg/L)", value = 1.0, min = 0.01, step = 0.1),
            numericInput("sigma_prop_init","Startwert σ_prop (proportion)", value = 0.15, min = 0.0, step = 0.01),
            hr(),
            h4("Ziele & Reporting"),
            numericInput("target_trough", "Ziel-Talspiegel (mg/L)", value = 8, min = 0, step = 0.5),
            actionButton("fit", "Modell fitten", class = "btn-primary w-100 mt-2"),
            actionButton("render_report", "PDF-Report erstellen", class = "btn-secondary w-100 mt-2")
          ),
          card(
            card_header("Ergebnisse"),
            card_body(
              div(class = "mb-2", tags$small("Hinweis: Demo-Software, keine klinische Anwendung!")),
              fluidRow(
                column(6, tableOutput("param_table")),
                column(6, tableOutput("dose_rec_table")),
        column(12, tableOutput("next_time_table"))
              ),
              tabsetPanel(
                tabPanel("Diagnose",
                  fluidRow(
                    column(6, tableOutput("diag_summary")),
                    column(6, tableOutput("diag_flags"))
                  ),
                  fluidRow(
                    column(6, plotOutput("diag_trace_CL", height = 260)),
                    column(6, plotOutput("diag_trace_Vc", height = 260))
                  ),
                  fluidRow(
                    column(6, plotOutput("diag_rank_CL", height = 260)),
                    column(6, plotOutput("diag_rank_Vc", height = 260))
                  )
                ),


                tabPanel("Datenintegration",
                  fluidRow(
                    column(6,
                      h4("FHIR · TDM-Observations"),
                      textInput("fhir_base", "FHIR Base URL", value = ""),
                      passwordInput("fhir_token", "Bearer Token (optional)", value = ""),
                      textInput("fhir_patient", "Patient ID", value = ""),
                      uiOutput("fhir_loinc_ui"),
                      actionButton("fhir_fetch", "Fetch"),
                      tableOutput("fhir_tdm_table"),
                      actionButton("use_fhir_as_obs", "In TDM-Inputs übernehmen")
                    ),
                    column(6,
                      h4("Antibiogramm (CSV)"),
                      fileInput("abg_file", "Upload CSV (drug,mic,prob)", accept = ".csv"),
                      uiOutput("abg_drug_ui"),
                      actionButton("use_abg_as_micdist", "Als MIC-Verteilung übernehmen")
                      hr(),
                      h4("Antibiogramm (DB)"),
                      actionButton("abg_db_refresh", "Liste aktualisieren"),
                      uiOutput("abg_db_ui"),
                      actionButton("use_abg_db", "DB-Verteilung übernehmen"),
                      hr(),
                      actionButton("abg_db_import", "CSV in DB importieren")

                    )
                  )
                ),
                
                tabPanel("Optimierung",
                  fluidRow(
                    column(5, tableOutput("opt_rec_table")),
                    column(7, plotOutput("opt_pareto_plot", height = 320))
                  ),
                  fluidRow(
                    column(6, plotOutput("opt_heatmap_dose_tinf", height = 320)),
                    column(6, plotOutput("opt_heatmap_dose_tau", height = 320))
                  ),
                  fluidRow(
                    column(12, DTOutput("opt_grid_dt"))
                  )
                ),

                tabPanel("Posterior-Zusammenfassung", DTOutput("posterior_dt")),
                tabPanel("Konz.-Zeit-Plot", plotOutput("ct_plot", height = 420)),
                tabPanel("Log", DTOutput("audit_dt"))
              ),
              downloadButton("dl_draws", "Posterior-Draws (CSV)")
            )
          )
        )
      ),
      nav_panel("Admin",
        layout_columns(
          col_widths = c(6,6),
          card(
            card_header("Priors-Datenbank"),
            card_body(
              uiOutput("prior_editor_ui"),
              DTOutput("priors_dt"),
              downloadButton("dl_priors", "Priors exportieren (JSON bundle)")
            )
          ),
          card(
            card_header("Systemstatus"),
            card_body(
              verbatimTextOutput("sys_status")
            )
          )
        )
      ),
      nav_panel("Info",
        card(card_body(markdown("
**TDMx-Open Advanced** — Forschungs-/Lehr-Demo.  
Features: Mehrkompartiment-Modelle, Kovariaten, Residualfehler-Modelle, Pop-Priors (JSON), Stan/JAGS Backends, PDF-Reports, Auth (shinymanager), Audit-Trail, Units-Checks.
        ")))
      )
    )
  )
}

# ---- Server ------------------------------------------------------------------
app_server <- function(input, output, session) {
  showModal(login_modal())

  # Auth (optional)
  user_info <- init_auth(enable = config$enable_auth)
  output$whoami <- renderUI({
    if (!is.null(user_info$user)) {
      tagList(tags$small(glue("Angemeldet: {user_info$user} (Rolle: {user_info$role})")))
    } else {
      tags$small("Gastmodus (Auth deaktiviert)")
    }
  })

  # Priors-DB
  priors_db <- reactiveVal(load_priors(config$priors_dir))

  output$drug_selector <- renderUI({
    drugs <- sort(names(priors_db()))
    selectInput("drug", "Wirkstoff", choices = drugs, selected = intersect(config$default_drug, drugs)[1])
  })

  # Beobachtungsdaten & Regimen
  obs <- reactive({
    tibble(
      time = parse_num_list(input$obs_times),
      conc = parse_num_list(input$obs_conc)
    ) %>% filter(is.finite(time), is.finite(conc)) %>% arrange(time)
  })

  regimen <- reactive({
    list(dose = req(input$dose), tau = req(input$tau), tinf = req(input$tinf),
         n_doses = req(input$n_doses), start_time = req(input$start_time))
  })

  # Kovariaten
  covars <- reactive({
    list(age = input$age, weight = input$weight, crcl = input$crcl)
  })

  # Fit auslösen
fit_res <- eventReactive(input$fit, {
    req(nrow(obs())>0)
    drug <- input$drug
    pri <- req(priors_db())[[drug]]
    mdl <- input$model_type
    err <- input$error_model
    backend <- input$backend
    est_sig <- isTRUE(input$estimate_sigma)
    lloq <- ifelse(is.finite(input$lloq), input$lloq, NA_real_)
    log_event(config$audit_log_file, user_info, "fit_start", list(drug=drug, model=mdl, err=err, backend=backend))
    res <- run_fit(
      obs = obs(),
      regimen = regimen(),
      priors = pri,
      model_type = mdl,
      error_model = err,
      covariates = covars(),
      backend = backend,
      estimate_sigma = est_sig,
      sigma_init = list(add = input$sigma_add_init, prop = input$sigma_prop_init),
      blq_lloq = lloq,
      is_blq = blq_flags(),
      use_cache = isTRUE(input$use_cache)
    )
    log_event(config$audit_log_file, user_info, "fit_done", list(ok = !inherits(res, "try-error")))
    res
  }, ignoreInit = TRUE)

  # Diagnostik: PPC + Rhat/ESS table
  output$ppc_plot <- renderPlot({
    fr <- req(fit_res()); req(nrow(fr$draws) > 0)
    yrep <- yrep_matrix(fr$draws, obs(), regimen(), input$model_type, input$error_model, input$sigma_add_init, input$sigma_prop_init, nrep = 200)
    summ <- ppc_summary(yrep, obs()$conc)
    if (nrow(summ) == 0) return(NULL)
    plot(summ$mean, summ$obs, xlab = "Posterior mean (yrep)", ylab = "Observed", main = "PPC: Observed vs Predicted")
    abline(0,1,lty=2)
  })

  output$diag_table <- renderDT({
    fr <- req(fit_res())
    d <- diag_table_from_backend(fr$diagnostics)
    if (nrow(d) == 0) return(DT::datatable(data.frame(Hinweis="Keine Diagnostik verfügbar"), options=list(pageLength=5)))
    DT::datatable(d, options = list(pageLength = 5, scrollX = TRUE))
  })

  # Design: next optimal sampling time within next interval
  output$next_time_table <- renderTable({
    fr <- req(fit_res())
    reg <- regimen()
    s <- suggest_next_time(fr$draws, reg, input$model_type, window_from = 0.25, window_to = reg$tau - 0.1, by = 0.25)
    tibble::tibble(
      Vorschlag = "Nächster optimaler Samplingzeitpunkt (h)",
      Wert = round(s$t_best, 2)
    )
  })

  
  # ---- Datenintegration (Phase 5) ----

  output$fhir_loinc_ui <- renderUI({
    lm <- try(load_loinc_map(), silent = TRUE); if (inherits(lm, "try-error")) lm <- list(tdm=list())
    codes <- (lm$tdm[[input$drug]] %||% character(0))
    textInput("fhir_codes", "LOINC Codes (Komma)", value = paste(codes, collapse=","))
  })
  observeEvent(input$fhir_fetch, {
    req(nzchar(input$fhir_base), nzchar(input$fhir_patient))
    codes <- strsplit(input$fhir_codes, ",")[[1]] |> trimws()
    b <- try(fhir_get_observations_all(input$fhir_base, input$fhir_patient, codes, token = input$fhir_token), silent = TRUE)
    if (inherits(b, "try-error")) {
      output$fhir_tdm_table <- renderTable({ data.frame(Fehler="FHIR Fetch fehlgeschlagen") })
    } else {
      df <- fhir_observations_to_tdm(b, unit_map = load_loinc_map()$units)
      output$fhir_tdm_table <- renderTable({ df })
      rv$fhir_df <- df
    }
  })
  observeEvent(input$use_fhir_as_obs, {
    df <- req(rv$fhir_df)
    times <- paste(round(df$time_h,3), collapse = ", ")
    concs <- paste(round(df$conc,3), collapse = ", ")
    updateTextInput(session, "obs_times", value = times)
    updateTextInput(session, "obs_conc", value = concs)
  })
  observeEvent(input$abg_file, {
    if (is.null(input$abg_file)) return()
    df <- read_antibiogram_csv(input$abg_file$datapath)
    rv$abg_df <- df
    output$abg_drug_ui <- renderUI({
      selectInput("abg_drug", "Drug", choices = unique(df$drug), selected = input$drug)
    })
  })
  observeEvent(input$use_abg_as_micdist, {
    df <- req(rv$abg_df); dr <- input$abg_drug %||% input$drug
    txt <- antibiogram_to_text(df, dr)
    try({ updateTextInput(session, "mic_dist", value = txt) }, silent = TRUE)
  })

  
  # ---- Optimierung ----
  observe({
    if (!isTruthy(input$opt_dose_min)) updateNumericInput(session, "opt_dose_min", value = max(50, 0.25*input$dose))
    if (!isTruthy(input$opt_dose_max)) updateNumericInput(session, "opt_dose_max", value = 4*input$dose)
    if (!isTruthy(input$opt_tau_min))  updateNumericInput(session, "opt_tau_min",  value = max(4, 0.5*input$tau))
    if (!isTruthy(input$opt_tau_max))  updateNumericInput(session, "opt_tau_max",  value = 2*input$tau)
  })

  opt_tinf_seq <- reactive({
    base <- c()
    if ("Bolus" %in% input$opt_strategies)       base <- c(base, 0.0)
    if ("Kurzinfusion" %in% input$opt_strategies) base <- c(base, 0.5)
    if ("Verlängert" %in% input$opt_strategies)   base <- c(base, 3.0, 4.0)
    if ("Kontinuierlich" %in% input$opt_strategies) base <- c(base, NaN)
    unique(base)
  })

  run_opt_res <- eventReactive(input$run_opt, {
    fr <- req(fit_res()); req(nrow(fr$draws) > 0)
    dseq <- seq(input$opt_dose_min, input$opt_dose_max, length.out = input$opt_dose_steps)
    tseq <- seq(input$opt_tau_min, input$opt_tau_max, length.out = input$opt_tau_steps)
    tinf_seq <- opt_tinf_seq()
    opt <- optimize_regimen(
      draws = fr$draws,
      base_regimen = regimen(),
      model_type = input$model_type,
      target_def = target_def(),
      MIC = req(input$mic),
      dose_seq = dseq,
      tau_seq = tseq,
      tinf_seq = tinf_seq,
      allow_cont = isTRUE(input$opt_allow_cont),
      max_daily_inf_h = input$opt_max_inf_h,
      max_daily_dose_mg = input$opt_max_daily_dose,
      max_interactions = input$opt_max_interactions,
      risk_type = input$opt_risk_type,
      risk_limit = input$opt_risk_limit,
      pta_min = input$opt_pta_min
    )
    opt
  }, ignoreInit = TRUE)

  output$opt_rec_table <- renderTable({
    opt <- req(run_opt_res())
    if (is.null(opt$rec)) return(tibble::tibble(Hinweis = "Keine Regime gefunden."))
    r <- opt$rec
    tibble::tibble(
      Empfehlung = c("Strategie","Dosis (mg)","τ (h)","tinf (h)","PTA","Risiko","Infusionszeit/Tag (h)","Tagesdosis (mg)","Gaben/Tag"),
      Wert = c(r$strategy, round(r$dose), round(r$tau,2), round(r$tinf,2), sprintf('%.1f%%', 100*r$PTA),
               sprintf('%.1f%%', 100*r$Risk), round(r$daily_inf_h,2), round(r$daily_dose), round(r$interactions,1))
    )
  })

  output$opt_pareto_plot <- renderPlot({
    opt <- req(run_opt_res()); req(nrow(opt$pareto) > 0)
    df <- opt$grid
    pare <- opt$pareto
    plot(df$Risk, df$PTA, xlab = "Risiko", ylab = "PTA", main = "Pareto: Risiko vs PTA")
    points(pare$Risk, pare$PTA, pch = 19)
    abline(h = input$opt_pta_min, lty = 2)
  })

  output$opt_grid_dt <- renderDT({
    opt <- req(run_opt_res()); req(nrow(opt$grid) > 0)
    g <- opt$grid
    g$PTA <- round(100*g$PTA,1); g$Risk <- round(100*g$Risk,1)
    DT::datatable(g, options = list(pageLength = 8, scrollX = TRUE))
  })

  output$opt_heatmap_dose_tinf <- renderPlot({
    fr <- req(fit_res()); req(nrow(fr$draws) > 0)
    dseq <- seq(input$opt_dose_min, input$opt_dose_max, length.out = input$opt_dose_steps)
    tinfs <- opt_tinf_seq()
    df <- pta_heatmap_data(fr$draws, regimen(), input$model_type, target_def(), req(input$mic), dseq, input$tau, tinfs[is.finite(tinfs)])
    if (nrow(df) == 0) return(NULL)
    ggplot2::ggplot(df, ggplot2::aes(x = dose, y = tinf, fill = PTA)) + ggplot2::geom_tile() +
      ggplot2::scale_fill_gradient(limits = c(0,1)) + ggplot2::labs(title = "PTA Heatmap: Dosis vs tinf (τ fix)", x="Dosis (mg)", y="tinf (h)")
  })

  output$opt_heatmap_dose_tau <- renderPlot({
    fr <- req(fit_res()); req(nrow(fr$draws) > 0)
    dseq <- seq(input$opt_dose_min, input$opt_dose_max, length.out = input$opt_dose_steps)
    tseq <- seq(input$opt_tau_min, input$opt_tau_max, length.out = input$opt_tau_steps)
    df <- pta_heatmap_data_tau(fr$draws, regimen(), input$model_type, target_def(), req(input$mic), dseq, tseq, input$tinf)
    if (nrow(df) == 0) return(NULL)
    ggplot2::ggplot(df, ggplot2::aes(x = dose, y = tau, fill = PTA)) + ggplot2::geom_tile() +
      ggplot2::scale_fill_gradient(limits = c(0,1)) + ggplot2::labs(title = "PTA Heatmap: Dosis vs τ (tinf fix)", x="Dosis (mg)", y="τ (h)")
  })

  
  # ---- Antibiogramm (DB) ----
  observeEvent(input$abg_db_refresh, {
    try({
      drugs <- antibiogram_drugs_db()
      output$abg_db_ui <- renderUI({
        selectInput("abg_db_drug", "Drug (DB)", choices = drugs, selected = input$drug)
      })
    }, silent = TRUE)
  }, ignoreInit = FALSE)

  observeEvent(input$use_abg_db, {
    try({
      dr <- input$abg_db_drug %||% input$drug
      df <- antibiogram_from_db(dr)
      txt <- antibiogram_to_text(df, dr)
      updateTextInput(session, "mic_dist", value = txt)
      try({ updateTextInput(session, "mic_distribution", value = txt) }, silent = TRUE)
    }, silent = TRUE)
  })

  observeEvent(input$abg_db_import, {
    req(input$abg_file)
    try({
      res <- antibiogram_import_to_db(input$abg_file$datapath, source = "ui-upload")
      showNotification(sprintf("Import OK: %d Zeilen (Version %s)", res$n, res$version), type = "message")
      session$sendCustomMessage("abg_db_refresh", TRUE)
    }, silent = TRUE)
  })

  
  # ---- HMC Options ----
  observe({
    opts <- list(
      chains = input$hmc_chains %||% 4L,
      iter_warmup = input$hmc_warmup %||% 1000L,
      iter_sampling = input$hmc_sampling %||% 1000L,
      adapt_delta = input$hmc_adapt_delta %||% 0.9,
      max_treedepth = input$hmc_max_treedepth %||% 12L
    )
    options(tdmx_hmc = opts)
  })

  
  # ---- Diagnose ----
  output$diag_summary <- renderTable({
    fr <- req(fit_res()); d <- fr$diagnostics
    if (is.null(d) || is.null(d$summary)) return(data.frame(Hinweis = "Keine Stan-Diagnostik verfügbar (z. B. Laplace/ADVI)."))
    as.data.frame(d$summary)
  })

  output$diag_flags <- renderTable({
    fr <- req(fit_res()); d <- fr$diagnostics
    if (is.null(d)) return(data.frame(Hinweis = "Keine Diagnostik verfügbar"))
    tibble::tibble(
      Metrik = c("Divergenzen", "max_treedepth Hits", "Stepsize"),
      Wert   = c(as.integer(d$divergences %||% NA), as.integer(d$treedepth_hits %||% NA), as.numeric(d$stepsize %||% NA))
    )
  })

  output$diag_trace_CL <- renderPlot({
    fr <- req(fit_res()); req(ncol(fr$draws) > 0)
    if (!"CL" %in% colnames(fr$draws)) return(NULL)
    y <- fr$draws$CL
    plot(y, type = "l", main = "Trace: CL", xlab = "Iterationen", ylab = "CL")
  })

  output$diag_trace_Vc <- renderPlot({
    fr <- req(fit_res()); if (!"Vc" %in% colnames(fr$draws)) return(NULL)
    y <- fr$draws$Vc
    plot(y, type = "l", main = "Trace: Vc", xlab = "Iterationen", ylab = "Vc")
  })

  output$diag_rank_CL <- renderPlot({
    fr <- req(fit_res()); if (!"CL" %in% colnames(fr$draws)) return(NULL)
    y <- fr$draws$CL
    n <- length(y); ranks <- rank(y, ties.method = "average")/n
    hist(ranks, breaks = 20, main = "Rank-Hist: CL", xlab = "rank", ylab = "freq")
  })

  output$diag_rank_Vc <- renderPlot({
    fr <- req(fit_res()); if (!"Vc" %in% colnames(fr$draws)) return(NULL)
    y <- fr$draws$Vc
    n <- length(y); ranks <- rank(y, ties.method = "average")/n
    hist(ranks, breaks = 20, main = "Rank-Hist: Vc", xlab = "rank", ylab = "freq")
  })

  
  observeEvent(input$auth_do_login, {
    u <- input$auth_user; p <- input$auth_pass
    ok <- try(auth_check(u, p), silent = TRUE)
    if (isTRUE(ok)) {
      users <- credentials_load()
      role <- "viewer"
      for (usr in users$users) if (identical(usr$username, u)) { role <- usr$role %||% "viewer"; break }
      auth_set_user(session, u, role)
      removeModal()
      audit_event("login", list(role = role), session = session)
    } else {
      showNotification("Login fehlgeschlagen", type = "error")
    }
  })

  # TTL enforcement
  observe({
    invalidateLater(5000, session)
    if (is.null(session$userData$expire_at)) return()
    exp <- try(session$userData$expire_at(), silent = TRUE)
    if (!inherits(exp, "try-error") && !is.null(exp) && Sys.time() > exp) {
      showNotification("Session abgelaufen. Bitte neu anmelden.", type = "warning")
      auth_logout(session, reason = "ttl_expired")
      showModal(login_modal("Session abgelaufen – Login"))
    }
  })

  
  # ---- Audit Hooks ----
  observeEvent(input$run_fit, {
    payload <- list(drug = input$drug, backend = input$backend, model = input$model_type, n_obs = length(strsplit(input$obs_conc %||% "", ",")[[1]]))
    audit_event("fit_run", payload, session = session)
  }, ignoreInit = TRUE)

  observeEvent(input$run_opt, {
    payload <- list(drug = input$drug, pta_min = input$opt_pta_min, strategies = input$opt_strategies)
    audit_event("optimize_run", payload, session = session)
  }, ignoreInit = TRUE)

  observeEvent(input$use_fhir_as_obs, {
    n <- try(nrow(rv$fhir_df), silent = TRUE); if (inherits(n,"try-error") || is.null(n)) n <- NA_integer_
    payload <- list(loinc = input$fhir_codes, n = n, patient = input$fhir_patient)
    audit_event("ehr_adopt", payload, session = session)
  }, ignoreInit = TRUE)

  observeEvent(input$fhir_fetch, {
    payload <- list(base = input$fhir_base, patient = input$fhir_patient, loinc = input$fhir_codes)
    audit_event("ehr_fetch", payload, session = session)
  }, ignoreInit = TRUE)

  observeEvent(input$abg_db_import, {
    payload <- list(source = "ui-upload", file = input$abg_file$name %||% "unknown")
    audit_event("cfr_import", payload, session = session, require_reason = FALSE)
  }, ignoreInit = TRUE)

  observeEvent(input$use_abg_as_micdist, {
    payload <- list(source = "upload_panel", drug = input$abg_drug %||% input$drug)
    audit_event("cfr_use", payload, session = session)
  }, ignoreInit = TRUE)

  observeEvent(input$use_abg_db, {
    payload <- list(source = "db_panel", drug = input$abg_db_drug %||% input$drug)
    audit_event("cfr_use", payload, session = session)
  }, ignoreInit = TRUE)

  # Posterior-Draws Tabelle
  output$posterior_dt <- renderDT({
    fr <- req(fit_res())
    DT::datatable(as.data.frame(fr$draws), options = list(pageLength = 10, scrollX = TRUE))
  })

  # Plot
  output$ct_plot <- renderPlot({
    fr <- req(fit_res())
    reg <- regimen()
    grid <- seq(0, max(reg$start_time + reg$n_doses*reg$tau + reg$tau, max(obs()$time)+reg$tau), by = 0.1)
    pred <- predict_conc_grid(
      times = grid,
      regimen = reg,
      theta = fr$posterior_summary$median,
      model_type = input$model_type
    )
    ggplot() +
      geom_line(aes(x = grid, y = pred)) +
      geom_point(data = obs(), aes(x = time, y = conc)) +
      labs(x = "Zeit (h)", y = "Konzentration (mg/L)", title = "MAP/Posterior-Median vs. Beobachtungen") +
      theme_minimal(base_size = 12)
  })

  # Draws Download
  output$dl_draws <- downloadHandler(
    filename = function() paste0("tdmx_advanced_draws_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv"),
    content = function(file) {
      fr <- req(fit_res())
      readr::write_csv(as.data.frame(fr$draws), file)
    }
  )

  # Audit Log
  output$audit_dt <- renderDT({
    ensure_audit_file(config$audit_log_file)
    df <- readr::read_csv(config$audit_log_file, show_col_types = FALSE)
    DT::datatable(df, options = list(pageLength = 5, scrollX = TRUE))
  })

  # Report Render
  observeEvent(input$render_report, {
    fr <- req(fit_res())
    tmp <- tempfile(fileext = ".pdf")
    ok <- tryCatch(render_report_pdf(
      rmd = config$report_rmd,
      output_file = tmp,
      params = list(
        user = user_info$user %||% "guest",
        timestamp = as.character(Sys.time()),
        drug = input$drug,
        model_type = input$model_type,
        error_model = input$error_model,
        regimen = regimen(),
        covariates = covars(),
        posterior_summary = fr$posterior_summary,
        draws_head = head(as.data.frame(fr$draws), 10)
      )
    ), error = function(e) e)
    if (inherits(ok, "error")) {
      showNotification(paste("Report fehlgeschlagen:", ok$message), type = "error")
    } else {
      showModal(modalDialog(
        title = "Report erstellt",
        p("PDF wurde generiert. Klicken zum Download:"),
        tags$a("Download", href = ok, target = "_blank"),
        easyClose = TRUE
      ))
    }
  })

  # Admin Priors
  output$prior_editor_ui <- renderUI({
    tagList(
      selectInput("admin_drug", "Wirkstoff auswählen", choices = names(priors_db())),
      textAreaInput("admin_json", "JSON bearbeiten", width = "100%", height = "240px",
                    value = jsonlite::toJSON(priors_db()[[input$admin_drug %||% names(priors_db())[1]]], auto_unbox = TRUE, pretty = TRUE)),
      actionButton("save_prior", "Speichern", class = "btn-success")
    )
  })

  observeEvent(input$save_prior, {
    try({
      drug <- req(input$admin_drug)
      val <- jsonlite::fromJSON(req(input$admin_json))
      save_prior(config$priors_dir, drug, val)
      priors_db(load_priors(config$priors_dir))
      showNotification("Prior gespeichert.", type = "message")
      log_event(config$audit_log_file, user_info, "prior_saved", list(drug=drug))
    }, silent = TRUE)
  })

  output$priors_dt <- renderDT({
    db <- priors_db()
    flat <- lapply(names(db), function(k) {
      tibble(drug = k, n_comp = db[[k]]$n_comp, theta = paste(names(db[[k]]$theta), collapse = ","))
    }) %>% bind_rows()
    DT::datatable(flat, options = list(pageLength = 5))
  })

  output$dl_priors <- downloadHandler(
    filename = function() "priors_bundle.json",
    content = function(file) {
      jsonlite::write_json(priors_db(), path = file, auto_unbox = TRUE, pretty = TRUE)
    }
  )

  # Systemstatus
  output$sys_status <- renderText({
    backend_status()
  })
}

# ---- Run ---------------------------------------------------------------------
app <- shinyApp(app_ui(), app_server)
if (isTruthy(Sys.getenv("SHINY_TESTING"))) {
  app
} else {
  runApp(app, launch.browser = FALSE)
}
