
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
