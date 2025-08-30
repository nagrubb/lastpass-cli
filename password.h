#ifndef PASSWORD_H
#define PASSWORD_H

char *password_prompt(const char *prompt, const char *error, const char *description);
char *pinentry_unescape(const char *str);
char *pinentry_escape(const char *str);
char *password_prompt_with_touchid(const char *prompt, const char *error, const char *service_name, const char *account_name, const char *description);

#endif
