#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <ostream>
#include <sodium.h>
#include <sodium/crypto_pwhash.h>
#include <sqlite3.h>
#include <string>

int initialize_server(sqlite3 **DB);
int login(sqlite3 *DB, char username[], unsigned long long username_len, char password_hash[], unsigned long long password_hash_len);
