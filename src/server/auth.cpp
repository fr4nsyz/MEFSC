#include "../../include/auth.h"

int login(sqlite3 *DB, char username[], unsigned long long username_len, char password[],
          unsigned long long password_len) {

  sqlite3_stmt *stmt;

  const char *retrieve_hashed_pswd =
      "SELECT hashed_pswd FROM users WHERE username = ?";


  if (sqlite3_prepare_v2(DB, retrieve_hashed_pswd, -1, &stmt, nullptr) !=
      SQLITE_OK) {
    std::cerr << "unable to prepare retrieve_hashed_pswd" << sqlite3_errmsg(DB)
              << std::endl;
    return 1;
  }

  sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);

  if (sqlite3_step(stmt) != SQLITE_ROW) {
    std::cerr << "no match in DATABASE" << std::endl;
    return 1;
  }

  std::cout << sqlite3_errmsg(DB) << std::endl;

  const unsigned char *db_password_hash = sqlite3_column_text(stmt, 0);

  if (crypto_pwhash_str_verify((const char *)db_password_hash, password,
                               password_len) != 0) {

    std::cerr << "this is password_len" << password_len << "\n";
    /* wrong password */
    std::cerr << "YOUUU SHALL NOTTTT PASSSSSSSSSSS" << std::endl;
    return 1;
  }

  std::cout << "SUCCESSFUL LOGIN YIPPIEEE" << std::endl;

  sodium_memzero(username, username_len);
  sodium_memzero(password, password_len);

  sqlite3_finalize(stmt);

  return 0;
}

int initialize_server(sqlite3 **DB) {

  int exit = 0;

  exit = sqlite3_open("MEFSC_DB.db", DB);

  if (exit != 0) {
    std::cerr << "couldn't open database" << std::endl;
    return 1;
  }

  return 0;
}
