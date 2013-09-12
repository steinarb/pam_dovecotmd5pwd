/*
 *
 * A PAM module that hooks into password updates and uses them
 * to update the HMAC-MD5 passwords used by dovecot for CRAM-MD5
 * authentication.
 *
 * Copyright (C) 2013  Steinar Bang
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <syslog.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>

#define PAM_SM_PASSWORD

#include <security/pam_modules.h>

/* Constants for this file */
#define DEFAULT_PASSWD_FILE_LOCATION "/etc/dovecot/cram-md5.pwd"
#define STRING_BUF_LEN 2048
#define CRAM_MD5_START "{CRAM-MD5}"

/* Predeclaring functions further down in the file. */
const char* hmac_md5_encode(const char* password, char* buffer);
int is_valid_encoded_password(const char* encoded_password);
int write_new_password(const char* passwd_file_name, const char* username, const char* encoded_password);
int file_exists(const char* filename);


PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char* password_file_name = DEFAULT_PASSWD_FILE_LOCATION;
    const char* username;
    const char* password;
    const char* encoded_password;
    char command_output_buffer[STRING_BUF_LEN];
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

        if (!write_new_password(password_file_name, username, encoded_password)) {
            /* Report the failure, but do not fail the module */
            char buf[STRING_BUF_LEN];
            sprintf(buf, "Failed to update dovecot cram-md5 password for %s", username);
            syslog(LOG_ERR, buf);
        }
    }

    return PAM_SUCCESS;
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

/*
 * Copy the contents of the existing passwd_file_name to a temp file in the
 * same directory as the existing password file.  Preserve the ownership
 * and access rights of the original password file.  Then acquire a file
 * lock on the password file and swap the new file for the old.
 */
int
write_new_password(const char* passwd_file_name, const char* username, const char* encoded_password) {
    int status = 1;

    if (file_exists(passwd_file_name)) {
        /* Replace the password for a user in an existing password file. */
        char tmp_passwd_file_name[STRING_BUF_LEN];
        sprintf(tmp_passwd_file_name, "%sXXXXXX", passwd_file_name);
        mktemp(tmp_passwd_file_name);

        FILE* tmp_passwd_file = fopen(tmp_passwd_file_name, "w");
        if (tmp_passwd_file != NULL) {
            FILE* passwd_file = fopen(passwd_file_name, "r");
            if (passwd_file != NULL) {
                char line_buf[STRING_BUF_LEN];
                char username_match[STRING_BUF_LEN];
                sprintf(username_match, "%s:", username);
                while (fgets(line_buf, STRING_BUF_LEN, passwd_file) != NULL) {
                    if (strncmp(line_buf, username_match, strlen(username_match)) != 0) {
                        /* Not a match for the user, just copy the line from the old file */
                        fputs(line_buf, tmp_passwd_file);
                    } else {
                        /* A match for the user, write a new line with the new password */
                        fprintf(tmp_passwd_file, "%s:%s", username, encoded_password);
                    }
                }

                fclose(passwd_file);
            } else {
                /* failure return code.  Failed to open the original passwd file for read */
                status = 0;
            }

            fclose(tmp_passwd_file);

            if (!status) {
                /* Couldn't read the existing password file, removing the b0rked temp file */
                remove(tmp_passwd_file_name);
            }
        } else {
            /* failure return code.  Failed to open the temp passwd file for write */
            status = 0;
        }

        if (status) {
            /* Make sure the temp file has the same ownership as the old password file (permissions are restricted by PAM) */
            struct stat original_passwd_file_stat;
            stat(passwd_file_name, &original_passwd_file_stat);
            chown(tmp_passwd_file_name, original_passwd_file_stat.st_uid, original_passwd_file_stat.st_gid);

            char lock_file_name[STRING_BUF_LEN];
            sprintf(lock_file_name, "%s.lock", passwd_file_name);
            FILE* lock_file = fopen(lock_file_name, "w");
            if (lock_file != NULL) {
                /* remove the original file and swap in the new one in its place */
                remove(passwd_file_name);
                rename(tmp_passwd_file_name, passwd_file_name);

                /* close and clean up the lock file */
                fclose(lock_file);
                remove(lock_file_name);
            } else {
                /* failed to aquire the lock file.  Cleaning up the temp file and set status to failure */
                remove(tmp_passwd_file_name);
                status = 0;
            }
        }
    } else {
        /* The original password file didn't exist.  Create a new one. */
        FILE* passwd_file = fopen(passwd_file_name, "w");
        if (passwd_file != NULL) {
            fprintf(passwd_file, "%s:%s", username, encoded_password);
            fclose(passwd_file);

            /* If user "dovecot" exists, make it the owner of the password file */
            struct passwd* dovecot_pw = getpwnam("dovecot");
            if (dovecot_pw != NULL) {
                chown(passwd_file_name, dovecot_pw->pw_uid, dovecot_pw->pw_gid);
            }
        } else {
            /* Unable to create a password file.  Return an error. */
            status = 0;
        }
    }

    return status;
}

int
file_exists(const char* filename) {
    struct stat dummy;
    return (stat(filename, &dummy) == 0);
}
