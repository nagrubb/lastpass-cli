/*
 * C wrapper for TouchID and Keychain integration
 *
 * Copyright (C) 2024 LastPass.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files, then also delete it here.
 *
 * See LICENSE.OpenSSL for more details regarding this exception.
 */

#include "touchid.h"

#ifdef __APPLE__

// These functions are implemented in touchid.m
extern bool touchid_init_impl(void);
extern bool touchid_store_password_impl(const char *service_name, const char *account_name, const char *password);
extern bool touchid_retrieve_password_impl(const char *service_name, const char *account_name, char **password_out);
extern bool touchid_delete_password_impl(const char *service_name, const char *account_name);
extern bool touchid_is_available_impl(void);
extern bool touchid_password_exists_impl(const char *service_name, const char *account_name);
extern bool touchid_prompt_for_authentication_impl(const char *reason);
extern void touchid_cleanup_impl(void);

bool touchid_init(void)
{
    return touchid_init_impl();
}

bool touchid_store_password(const char *service_name, const char *account_name, const char *password)
{
    return touchid_store_password_impl(service_name, account_name, password);
}

bool touchid_retrieve_password(const char *service_name, const char *account_name, char **password_out)
{
    return touchid_retrieve_password_impl(service_name, account_name, password_out);
}

bool touchid_delete_password(const char *service_name, const char *account_name)
{
    return touchid_delete_password_impl(service_name, account_name);
}

bool touchid_is_available(void)
{
    return touchid_is_available_impl();
}

bool touchid_password_exists(const char *service_name, const char *account_name)
{
    return touchid_password_exists_impl(service_name, account_name);
}

bool touchid_prompt_for_authentication(const char *reason)
{
    return touchid_prompt_for_authentication_impl(reason);
}

void touchid_cleanup(void) 
{ 
    touchid_cleanup_impl();
}

#else

// Stub implementations for non-Apple platforms
bool touchid_init(void) { return false; }
bool touchid_store_password(const char *service_name, const char *account_name, const char *password) { return false; }
bool touchid_retrieve_password(const char *service_name, const char *account_name, char **password_out) { return false; }
bool touchid_delete_password(const char *service_name, const char *account_name) { return false; }
bool touchid_is_available(void) { return false; }
bool touchid_password_exists(const char *service_name, const char *account_name) { return false; }
bool touchid_prompt_for_authentication(const char *reason) { return false; }
void touchid_cleanup(void) { }

#endif
