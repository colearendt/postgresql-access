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

permissions_rename <- list(schema="Schema", name="Name", type="Type", access="Access privileges", column="Column privileges", policies = "Policies")
permissions <- permissions_r %>% collect() %>%
  rename(!!!permissions_rename)

permissions_tall <- permissions %>%
  select(-column, - policies) %>%
  separate_rows(access, sep = "\n") %>%
  separate(access, sep = "=", into = c("role", "permission_raw"), remove = FALSE) %>%
  separate(permission_raw, sep = "/", into = c("permission_raw", "owner"), remove = TRUE) %>%
  separate_rows(permission_raw, sep = "") %>%
  filter(permission_raw != "") %>%
  mutate(
    permission = case_when(
      permission_raw == "r" ~ "SELECT",
      permission_raw == "a" ~ "INSERT",
      permission_raw == "w" ~ "UPDATE",
      permission_raw == "d" ~ "DELETE",
      permission_raw == "D" ~ "TRUNCATE",
      permission_raw == "x" ~ "REFERENCES",
      permission_raw == "t" ~ "TRIGGER",
      permission_raw == "C" ~ "CREATE",
      permission_raw == "c" ~ "CONNECT",
      permission_raw == "T" ~ "TEMPORARY",
      permission_raw == "X" ~ "EXECUTE",
      permission_raw == "U" ~ "USAGE",
      TRUE ~ "UNKNOWN"
    )
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

