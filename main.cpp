#include <iostream>
#include <sqlite3.h>
#include <string>
#include <sodium.h>


const std::string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const std::string DIGITS = "0123456789";

bool checkTableExists(sqlite3 *db) {
    sqlite3_stmt *stmt;
    std::string sql = "SELECT name FROM sqlite_master WHERE type='table' AND name=?";
    
    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // Bind the table name to the SQL query
    sqlite3_bind_text(stmt, 1, "passwords", -1, SQLITE_STATIC);
    
    // Execute the query and check if any row is returned
    int result = sqlite3_step(stmt);
    bool exists = (result == SQLITE_ROW);
    
    // Finalize the statement
    sqlite3_finalize(stmt);
    
    return exists;
} 

int getMasterPassword(sqlite3 *db, std::string &masterPassword) {
    
    // Check if table exists, if it does, continue, if not, ask user to create a master password
    if (!checkTableExists(db)) {
        std::cout << "Recommended cryptographically secure random password: ";
        if (sodium_init() == -1) {
            std::cerr << "Failed to initialize libsodium" << std::endl;
            return 1;
        }
        std::string password;
        // Generate a random password
        // n letters, hyphen, n more letters, hyphen, n more letters * n
        // where n is also a random number betwen 1 and 5
        // password length is a random number between 8 and 20
        int passwordLength = randombytes_uniform(12) + 8;
        for (int i = 0; i < passwordLength; i) {
            int n = randombytes_uniform(4) + 3;
            for (int j = 0; j < n; j++) {
                password += letters[randombytes_uniform(letters.size())];
            }
            password += "-";
            n = randombytes_uniform(4) + 3;
            for (int j = 0; j < n; j++) {
                password += letters[randombytes_uniform(letters.size())];
            }
            password += "-";
            n = randombytes_uniform(3) + 1;
            for (int j = 0; j < n; j++) {
                password += DIGITS[randombytes_uniform(DIGITS.size())];
            }
            password += "-";
            i = password.size();
        }
        
        password = password.substr(0, password.size() - 1);
        std::cout << password << std::endl;
        
        std::cout << "Enter a master password: ";
        std::cin >> masterPassword;
        std::string sql = "CREATE TABLE passwords (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT, salt TEXT, nonce TEXT);";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to create table: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }
        sqlite3_finalize(stmt);

        // take the master password, use KDF to generate a key which will be used to encrypt the passwords
        
        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof(salt));

        unsigned char key[crypto_secretbox_KEYBYTES];
        if (crypto_pwhash(key, sizeof(key), masterPassword.c_str(), masterPassword.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
            std::cerr << "Failed to generate key" << std::endl;
            return 1;
        }

        // Insert the salt into the database
        sql = "INSERT INTO passwords (website, username, password, salt, nonce) VALUES ('master', 'master', 'master', ?,  'master');";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }
        // Save salt and key to the database
        sqlite3_bind_blob(stmt, 1, salt, sizeof(salt), SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to insert salt: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }


        sqlite3_finalize(stmt);

        // Copy the key to masterPassword
        masterPassword = std::string(key, key + sizeof(key));

        // Encrypt the phrase "Hello, world!" using the key
        unsigned char nonce[crypto_secretbox_NONCEBYTES];

        randombytes_buf(nonce, sizeof(nonce));

        std::string message = "Hello, world!";

        unsigned char ciphertext[message.size() + crypto_secretbox_MACBYTES];
        if (crypto_secretbox_easy(ciphertext, (unsigned char *)message.c_str(), message.size(), nonce, key) != 0) {
            std::cerr << "Failed to encrypt message" << std::endl;
            return 1;
        }

        // Save the encrypted message to the database
        sql = "INSERT INTO passwords (website, username, password, salt, nonce) VALUES ('check', 'check', ?, 'check', ?);";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }
        sqlite3_bind_blob(stmt, 1, ciphertext, sizeof(ciphertext), SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, nonce, sizeof(nonce), SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Failed to insert encrypted message: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }

        sqlite3_finalize(stmt);




    } else {
        std::cout << "Enter the master password: ";
        std::cin >> masterPassword;
        // Get the salt from the database
        std::string sql = "SELECT salt FROM passwords WHERE website='master';";
        sqlite3_stmt *stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }
        if (sqlite3_step(stmt) != SQLITE_ROW) {
            std::cerr << "Failed to get salt: " << sqlite3_errmsg(db) << std::endl;
            return 1;
        }

        const unsigned char *salt = sqlite3_column_text(stmt, 0);
        unsigned char key[crypto_secretbox_KEYBYTES];
        if (crypto_pwhash(key, sizeof(key), masterPassword.c_str(), masterPassword.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
            std::cerr << "Failed to generate key" << std::endl;
            return 1;
        }

        sqlite3_finalize(stmt);
        // Copy the key to masterPassword
        masterPassword = std::string(key, key + sizeof(key));
    }

    return 0;
}


int main()
{
    std::string masterPassword;
    // Access the sqlite3 db
    sqlite3 *db;
    int returnCode = sqlite3_open("test.db", &db);
    
    if (returnCode)
    {
        std::cerr << "Error opening SQLite3 database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    std::cout << "Opened database " << std::endl;

    if (getMasterPassword( db, masterPassword) != 0) {
        return 1;
    }


    // Decrypt the check message
    std::string sql = "SELECT password, nonce FROM passwords WHERE website='check';";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        std::cerr << "Failed to get encrypted message: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    const unsigned char *ciphertext = sqlite3_column_text(stmt, 0);
    const unsigned char *nonce = sqlite3_column_text(stmt, 1);

    unsigned char decrypted[sqlite3_column_bytes(stmt, 0) - crypto_secretbox_MACBYTES];
    if (crypto_secretbox_open_easy(decrypted, ciphertext, sqlite3_column_bytes(stmt, 0), nonce, (unsigned char *)masterPassword.c_str()) != 0) {
        std::cerr << "Failed to decrypt message or password is wrong" << std::endl;
        return 1;
    }

    // Get number of stored passwords in the database
    sql = "SELECT COUNT(*) FROM passwords;";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        std::cerr << "Failed to get number of passwords: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    int numPasswords = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    
    std::cout << "Number of stored passwords: " << numPasswords << std::endl;
    
    while (1)
    {
        std::cout << "Press enter to view the stored passwords, type 'add' to add a new password, or type 'exit' to exit.\nSearch for a password by typing 'search' followed by the website name.\n";
        std::string command;
        std::cin >> command;
        if (command == "exit") {
            return 0;
        } else if (command == "add") {
            std::string website, username, password;
            std::cout << "Enter the website: ";
            std::cin >> website;
            std::cout << "Enter the username: ";
            std::cin >> username;
            std::cout << "Enter the password: ";
            std::cin >> password;
            
            // Encrypt the password
            unsigned char nonce[crypto_secretbox_NONCEBYTES];
            randombytes_buf(nonce, sizeof(nonce));
            
            unsigned char ciphertext[password.size() + crypto_secretbox_MACBYTES];
            if (crypto_secretbox_easy(ciphertext, (unsigned char *)password.c_str(), password.size(), nonce, (unsigned char *)masterPassword.c_str()) != 0) {
                std::cerr << "Failed to encrypt password" << std::endl;
                return 1;
            }
            
            // Insert the encrypted password into the database
            sql = "INSERT INTO passwords (website, username, password, salt, nonce) VALUES (?, ?, ?, 'check', ?);";
            if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
                std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
                return 1;
            }
            sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 3, ciphertext, sizeof(ciphertext), SQLITE_STATIC);
            sqlite3_bind_blob(stmt, 4, nonce, sizeof(nonce), SQLITE_STATIC);
            
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                std::cerr << "Failed to insert password: " << sqlite3_errmsg(db) << std::endl;
                return 1;
            }
            
            sqlite3_finalize(stmt);
        } else if (command == "search") {
            std::string website;
            std::cin >> website;
            
            // Get the encrypted password from the database
            sql = "SELECT username, password, nonce FROM passwords WHERE website=?;";
            if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
            {
                std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
                // return 1;
            }
            sqlite3_bind_text(stmt, 1, website.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_ROW)
            {
                std::cerr << "Failed to get password: " << sqlite3_errmsg(db) << std::endl;
                // return 1;
            }

            const unsigned char *username = sqlite3_column_text(stmt, 0);
            const unsigned char *ciphertext = sqlite3_column_text(stmt, 1);
            const unsigned char *nonce = sqlite3_column_text(stmt, 2);

            unsigned char decrypted[sqlite3_column_bytes(stmt, 1) - crypto_secretbox_MACBYTES];
            if (crypto_secretbox_open_easy(decrypted, ciphertext, sqlite3_column_bytes(stmt, 1), nonce, (unsigned char *)masterPassword.c_str()) != 0)
            {
                std::cerr << "Failed to decrypt password or password is wrong" << std::endl;
                // return 1;
            }

            std::cout << "Username: " << username << std::endl;
            std::cout << "Password: " << decrypted << std::endl;

            sqlite3_finalize(stmt);
        } else {
            std::cout << "invalid command" << std::endl;
        }
    }
        

    // Close the database
    sqlite3_close(db);



    return 0;
}
