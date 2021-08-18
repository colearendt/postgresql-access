library(tidyverse)
library(DBI)
library(odbc)
library(RPostgres)

config <- config::get("db")
con <- do.call(pool::dbPool, config)

dplyr::tibble(con, "information_schema.user_mappings")

library(dbplyr)
dplyr::tbl(con, in_schema("information_schema", "user_mappings"))

source("queries.R")

translate_permissions <- function(input) {
  case_when(
      input == "r" ~ "SELECT",
      input == "a" ~ "INSERT",
      input == "w" ~ "UPDATE",
      input == "d" ~ "DELETE",
      input == "D" ~ "TRUNCATE",
      input == "x" ~ "REFERENCES",
      input == "t" ~ "TRIGGER",
      input == "C" ~ "CREATE",
      input == "c" ~ "CONNECT",
      input == "T" ~ "TEMPORARY",
      input == "X" ~ "EXECUTE",
      input == "U" ~ "USAGE",
      TRUE ~ "UNKNOWN"
  )
}

split_permissions <- function(df, column) {
  column_q <- rlang::enquo(column)
  df %>%
    separate_rows(!!column_q, sep = "\n") %>%
    separate(!!column_q, sep = "=", into = c("role", "permission_raw"), remove = FALSE) %>%
    separate(permission_raw, sep = "/", into = c("permission_raw", "owner"), remove = TRUE) %>%
    separate_rows(permission_raw, sep = "") %>%
    filter(permission_raw != "" | is.na(permission_raw))
}

users_r <- tbl(con, user_query)
roles_r <-tbl(con,role_query)
schemas_r <- tbl(con, schema_query)
permissions_r <-tbl(con, permission_query)


# collect the data locally
users <- users_r %>% collect()
roles <- roles_r %>% collect()
roles_tall <- bind_rows(
  roles_r %>% filter(is.na(sql(array_length(memberof,1L)))) %>% collect(),
  roles_r %>% filter(!is.na(sql(array_length(memberof,1L)))) %>% mutate(member_roles=sql(unnest(memberof))) %>% collect()
)

schemas <- schemas_r %>% collect()

schemas_tall <- schemas %>%
  split_permissions(`Access privileges`) %>%
  mutate(permission = translate_permissions(permission_raw))

permissions_rename <- list(schema="Schema", name="Name", type="Type", access="Access privileges", column="Column privileges", policies = "Policies")
permissions <- permissions_r %>% collect() %>%
  rename(!!!permissions_rename)

permissions_tall <- permissions %>%
  select(-column, - policies) %>%
  split_permissions(access) %>%
  mutate(
    permission = translate_permissions(permission_raw)
  )

permissions_agg <- permissions_tall %>%
  group_by(schema,name,type,role,owner) %>%
  arrange(permission) %>%
  summarize(permission = paste(permission, sep = ",", collapse = ","))

permissions_profiles <- permissions_agg %>%
  group_by(schema, type, role, owner, permission) %>%
  summarize(names = list(name))

# sanity checks
stopifnot(roles_tall$rolname %in% roles$rolname) # have not dropped roles


# example queries
permissions_profiles %>% filter(role == "appuser_crud") %>% View()
permissions_profiles %>% filter(role == "appuser_select") %>% View()
permissions_profiles %>% filter(!role %in% c("appuser_crud","appuser_select")) %>% View()
