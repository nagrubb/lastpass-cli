/*
 * TouchID and Keychain integration for LastPass CLI
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

#ifdef __APPLE__

#import "touchid.h"
#import "util.h"
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <unistd.h>

static bool touchid_available = false;
static LAContext *auth_context = nil;

bool touchid_init_impl(void)
{
    if (auth_context != nil) {
        return touchid_available;
    }

    auth_context = [[LAContext alloc] init];
    if (!auth_context) {
        return false;
    }

    NSError *error = nil;
    touchid_available = [auth_context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&error];
    
    if (!touchid_available && error) {
        // TouchID not available, but we can still use Keychain without biometrics
        touchid_available = false;
    }

    return touchid_available;
}

bool touchid_store_password_impl(const char *service_name, const char *account_name, const char *password)
{
    if (!service_name || !account_name || !password) {
        return false;
    }

    // Convert C strings to NSString - these are autoreleased
    NSString *ns_service = [NSString stringWithUTF8String:service_name];
    NSString *ns_account = [NSString stringWithUTF8String:account_name];
    NSString *ns_password = [NSString stringWithUTF8String:password];
    
    if (!ns_service || !ns_account || !ns_password) {
        return false;
    }

    // Create query for the keychain
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [query setObject:ns_service forKey:(__bridge id)kSecAttrService];
    [query setObject:ns_account forKey:(__bridge id)kSecAttrAccount];
    [query setObject:ns_password forKey:(__bridge id)kSecValueData];
    [query setObject:(__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];

    // Try to add the item
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    
    if (status == errSecDuplicateItem) {
        // Item already exists, update it
        NSMutableDictionary *update_query = [[NSMutableDictionary alloc] init];
        [update_query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
        [update_query setObject:ns_service forKey:(__bridge id)kSecAttrService];
        [update_query setObject:ns_account forKey:(__bridge id)kSecAttrAccount];
        
        NSMutableDictionary *update_attributes = [[NSMutableDictionary alloc] init];
        [update_attributes setObject:ns_password forKey:(__bridge id)kSecValueData];
        
        status = SecItemUpdate((__bridge CFDictionaryRef)update_query, (__bridge CFDictionaryRef)update_attributes);
        
        // Release update objects
        [update_attributes release];
        [update_query release];
    }

    // Release allocated objects (NSStrings are autoreleased, don't release them)
    [query release];

    return status == errSecSuccess;
}

bool touchid_prompt_for_authentication_impl(const char *reason)
{
    if (!touchid_available || !auth_context) {
        return false;
    }
    
    NSString *ns_reason = @"access LastPass vault";

    if (reason) {
        ns_reason = [NSString stringWithUTF8String:reason];
    }

    // Create a semaphore to make this synchronous
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block bool auth_success = false;
    
    [auth_context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                localizedReason:ns_reason
                          reply:^(BOOL success, NSError *error) {
        if (success) {
            auth_success = true;
        } else {
            if (error) {
                NSLog(@"TouchID authentication failed: %@", error.localizedDescription);
            }
            auth_success = false;
        }
        dispatch_semaphore_signal(semaphore);
    }];
    
    // Wait for the authentication result
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    dispatch_release(semaphore);
    
    return auth_success;
}

bool touchid_retrieve_password_impl(const char *service_name, const char *account_name, char **password_out)
{
    if (!service_name || !account_name || !password_out) {
        return false;
    }

    // First, prompt for TouchID authentication
    if (!touchid_prompt_for_authentication_impl("access LastPass Master Password from Keychain")) {
        return false;
    }

    // Convert C strings to NSString - these are autoreleased
    NSString *ns_service = [NSString stringWithUTF8String:service_name];
    NSString *ns_account = [NSString stringWithUTF8String:account_name];

    if (!ns_service || !ns_account) {
        return false;
    }

    // Create query for the keychain
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [query setObject:ns_service forKey:(__bridge id)kSecAttrService];
    [query setObject:ns_account forKey:(__bridge id)kSecAttrAccount];
    [query setObject:(__bridge id)kSecReturnData forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
    [query setObject:(__bridge id)kSecUseDataProtectionKeychain forKey:(__bridge id)kSecUseDataProtectionKeychain];

    // Try to retrieve the item
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status != errSecSuccess || !result) {
        NSLog(@"Failed to retrieve item from Keychain: %d", (int)status);
        [query release];
        return false;
    }

    SecKeychainItemRef keychainItem = (__bridge SecKeychainItemRef)result;
    if (!keychainItem) {
        NSLog(@"Failed to get SecKeychainItem");
        CFRelease(result);
        [query release];
        return false;
    }

    // Get the password data from the keychain item
    UInt32 passwordLength = 0;
    void *passwordData = NULL;
    SecKeychainAttributeList * __nullable attrList = NULL;

        
    status = SecKeychainItemCopyContent(keychainItem, NULL, attrList, &passwordLength, &passwordData);
    if (status != errSecSuccess || !passwordData || passwordLength <= 0) {
        NSLog(@"Failed to extract password from SecKeychainItem: %d", (int)status);
        SecKeychainItemFreeContent(attrList, passwordData);
        CFRelease(result);
        [query release];
        return false;
    }

    // Convert the password data to NSData
    NSData *password_data = [NSData dataWithBytes:passwordData length:passwordLength];
    
    // Free the password data
    SecKeychainItemFreeContent(attrList, passwordData);
    
    // Convert to string
    NSString *ns_password = [[NSString alloc] initWithData:password_data encoding:NSUTF8StringEncoding];
    if (ns_password) {
        const char *password_cstr = [ns_password UTF8String];
        if (password_cstr) {
            *password_out = xstrdup(password_cstr);
            [ns_password release];
            [query release];
            CFRelease(result);
            return true;
        }
        [ns_password release];
    } 

    // Cleanup on failure
    [query release];
    CFRelease(result);
    return false;
}

bool touchid_delete_password_impl(const char *service_name, const char *account_name)
{
    if (!service_name || !account_name) {
        return false;
    }

    // Convert C strings to NSString - these are autoreleased
    NSString *ns_service = [NSString stringWithUTF8String:service_name];
    NSString *ns_account = [NSString stringWithUTF8String:account_name];
    
    if (!ns_service || !ns_account) {
        return false;
    }

    // Create query for the keychain
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [query setObject:ns_service forKey:(__bridge id)kSecAttrService];
    [query setObject:ns_account forKey:(__bridge id)kSecAttrAccount];

    // Delete the item
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
    
    // Release allocated objects (NSStrings are autoreleased, don't release them)
    [query release];
    
    return status == errSecSuccess;
}

bool touchid_is_available_impl(void)
{
    return touchid_available;
}

void touchid_cleanup_impl(void)
{
    if (auth_context != nil) {
        [auth_context release];
        auth_context = nil;
    }
    touchid_available = false;
}

bool touchid_password_exists_impl(const char *service_name, const char *account_name)
{
    if (!service_name || !account_name) {
        return false;
    }

    // Convert C strings to NSString - these are autoreleased
    NSString *ns_service = [NSString stringWithUTF8String:service_name];
    NSString *ns_account = [NSString stringWithUTF8String:account_name];
    
    if (!ns_service || !ns_account) {
        return false;
    }

    // Create query for the keychain
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    [query setObject:ns_service forKey:(__bridge id)kSecAttrService];
    [query setObject:ns_account forKey:(__bridge id)kSecAttrAccount];
    [query setObject:(__bridge id)kSecReturnData forKey:(__bridge id)kSecReturnData];
    [query setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];

    // Try to retrieve the item
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    
    if (status == errSecSuccess && result) {
        CFRelease(result);
        [query release];
        return true;
    }
    
    // Release allocated objects (NSStrings are autoreleased, don't release them)
    [query release];
    
    return false;
}

#else

// Stub implementations for non-Apple platforms
bool touchid_init(void) { return false; }
bool touchid_store_password(const char *service_name, const char *account_name, const char *password) { return false; }
bool touchid_retrieve_password(const char *service_name, const char *account_name, char **password_out) { return false; }
bool touchid_delete_password(const char *service_name, const char *account_name) { return false; }
bool touchid_is_available(void) { return false; }
bool touchid_password_exists(const char *service_name, const char *account_name) { return false; }
void touchid_cleanup(void) { }

#endif
