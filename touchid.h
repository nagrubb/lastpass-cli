#ifndef TOUCHID_H
#define TOUCHID_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __APPLE__
#define __TOUCHID_AVAILABLE__

/**
 * Initialize TouchID and Keychain integration
 * @return true if TouchID is available and properly configured
 */
bool touchid_init(void);

/**
 * Store a password in the Keychain
 * @param service_name The service name (e.g., "LastPass CLI")
 * @param account_name The account name (e.g., username)
 * @param password The password to store
 * @return true if successful, false otherwise
 */
bool touchid_store_password(const char *service_name, const char *account_name, const char *password);

/**
 * Retrieve a password from the Keychain using TouchID authentication
 * @param service_name The service name (e.g., "LastPass CLI")
 * @param account_name The account name (e.g., username)
 * @param password_out Pointer to store the retrieved password
 * @return true if successful, false otherwise
 */
bool touchid_retrieve_password(const char *service_name, const char *account_name, char **password_out);

/**
 * Delete a password from the Keychain
 * @param service_name The service name (e.g., "LastPass CLI")
 * @param account_name The account name (e.g., username)
 * @return true if successful, false otherwise
 */
bool touchid_delete_password(const char *service_name, const char *account_name);

/**
 * Check if TouchID is available on this system
 * @return true if TouchID is available, false otherwise
 */
bool touchid_is_available(void);

/**
 * Check if a password exists in the Keychain
 * @param service_name The service name (e.g., "LastPass CLI")
 * @param account_name The account name (e.g., username)
 * @return true if password exists, false otherwise
 */
bool touchid_password_exists(const char *service_name, const char *account_name);

/**
 * Prompt for TouchID authentication
 * @param reason The reason to display to the user for authentication
 * @return true if authentication succeeded, false otherwise
 */
bool touchid_prompt_for_authentication(const char *reason);

/**
 * Clean up TouchID resources
 * Should be called when shutting down the application
 */
void touchid_cleanup(void);

#else

// Stub implementations for non-Apple platforms
static inline bool touchid_init(void) { return false; }
static inline bool touchid_store_password(const char *service_name, const char *account_name, const char *password) { return false; }
static inline bool touchid_retrieve_password(const char *service_name, const char *account_name, char **password_out) { return false; }
static inline bool touchid_delete_password(const char *service_name, const char *account_name) { return false; }
static inline bool touchid_is_available(void) { return false; }
static inline bool touchid_password_exists(const char *service_name, const char *account_name) { return false; }
static inline bool touchid_prompt_for_authentication(const char *reason) { return false; }
static inline void touchid_cleanup(void) { }

#endif

#endif // TOUCHID_H
