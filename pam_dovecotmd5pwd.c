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
#include <string.h>

#define PAM_SM_PASSWORD

#include <security/pam_modules.h>

/* Constants for this file */
#define STRING_BUF_LEN 2048
#define CRAM_MD5_START "{CRAM-MD5}"

/* Predeclaring functions further down in the file. */
const char* hmac_md5_encode(const char* password, char* buffer);
int is_valid_encoded_password(const char* encoded_password);


PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char* username;
    const char* password;
    const char* encoded_password;
    char command_output_buffer[STRING_BUF_LEN];
    char buf[STRING_BUF_LEN];
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
        syslog(LOG_ERR, "cannot determine user name");
        return PAM_USER_UNKNOWN;
    }

    if (pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password) != PAM_SUCCESS) {
        syslog(LOG_ERR, "could not aquire a new password to set");
        return PAM_AUTHTOK_ERR;
    }

    /*
     * The pam_sm_chauthtok method is called twice from passwd.
     * The first time it is called, the new password hasn't been
     * requested yet, and the value is NULL.
     *
     * Only try to encode and set non-NULL passwords.
     */
    if (password != NULL) {
        encoded_password = hmac_md5_encode(password, command_output_buffer);
        if (!is_valid_encoded_password(encoded_password)) {
            syslog(LOG_ERR, "Unable to create an encoded password");
            return PAM_AUTHTOK_ERR;
        }

        sprintf(buf, "Username: %s  Password: %s  Encoded password: %s", username, password, encoded_password);
        syslog(LOG_ERR, buf);
    }

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

/*
 * Start a subprocess to get a HMAC-MD5 encoded
 * password from doveadm.
 */
const char*
hmac_md5_encode(const char* password, char* command_output) {
    char command_line[STRING_BUF_LEN];
    sprintf(command_line, "doveadm pw -s CRAM-MD5 -p \'%s\'", password);
    FILE* command_output_stream = popen(command_line, "r");
    if (command_output_stream == NULL) {
        /* Failed to create the subprocess. */
        return NULL;
    }

    if (fgets(command_output, STRING_BUF_LEN, command_output_stream) == NULL) {
        /* Failed to read a line from the subprocess. */
        pclose(command_output_stream);
        return NULL;
    }

    /* Close the pipe as soon as possible  to terminate the subprocess. */
    pclose(command_output_stream);

    return command_output;
}

int
is_valid_encoded_password(const char* encoded_password) {
    return
        strlen(encoded_password) > 0 ||
        strncmp(encoded_password, CRAM_MD5_START, strlen(CRAM_MD5_START)) == 0;
}
