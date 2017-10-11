/*
 * Get or delete AFS tokens.
 *
 * Here are the functions to get or delete AFS tokens, called by the various
 * public functions.  The functions to get tokens should run after a PAG is
 * created.  All functions here assume that AFS is running and k_hasafs() has
 * already been called.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <krb5/krb5.h>
#include <string.h>
#include <pwd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "args.h"
#include "logging.h"
#include "pam_options.h"

/*
 * Free the results of pam_getenvlist.
 */
static void pamkafs_free_envlist(char **env) {
    size_t i;

    for (i = 0; env[i] != NULL; ++i) {
        free(env[i]);
    }
    free(env);
}


/*
 * Given the PAM arguments and the passwd struct of the user we're
 * authenticating, see if we should ignore that user because they're root or
 * have a low-numbered UID and we were configured to ignore such users.
 * Returns true if we should ignore them, false otherwise.
 */
static bool pamkafs_should_ignore(struct pam_args *args, const struct passwd *pwd) {
    long minimum_uid = args->config->minimum_uid;

    if (args->config->ignore_root && strcmp("root", pwd->pw_name) == 0) {
        putil_debug(args, "ignoring root user");
        return true;
    } else {
        if ((minimum_uid > 0) && (pwd->pw_uid < (unsigned long)minimum_uid)) {
            putil_debug(args, "ignoring low-UID user (%lu < %ld)",
                        (unsigned long) pwd->pw_uid, minimum_uid);
            return true;
        } else {
            return false;
        }
    }
}

/*
 * If the kdestroy option is set and we were built with Kerberos support,
 * destroy the ticket cache after we successfully got tokens.
 */
static void maybe_destroy_cache(struct pam_args *args, const char *cache) {
    krb5_error_code ret;
    krb5_ccache ccache;

    if (!args->config->kdestroy)
        return;
    ret = krb5_cc_resolve(args->ctx, cache, &ccache);
    if (ret != 0) {
        putil_err_krb5(args, ret, "cannot open Kerberos ticket cache");
        return;
    }
    putil_debug(args, "destroying ticket cache");
    ret = krb5_cc_destroy(args->ctx, ccache);
    if (ret != 0)
        putil_err_krb5(args, ret, "cannot destroy Kerberos ticket cache");
}

/*
 * Load AFS keberos ticket into session keyring.
 * Does various sanity checks first, ensuring that we have
 * a Kerberos ticket cache, that we can resolve the username, and that we're
 * not supposed to ignore this user.
 *
 * Normally, set our flag data item if the tickets were successfully
 * set into the session keyring. This prevents a subsequent setcred or
 * open_session from doing anything and flags close_session to remove the token.
 * However, don't do this if the reinitialize flag is set, since in that case
 * we're refreshing a token we're not subsequently responsible for.
 * This fixes problems with sudo when it has pam_setcred enabled, since it
 * calls pam_setcred with PAM_REINITIALIZE_CRED first before calling
 * pam_open_session, and we don't want to skip the pam_open_session
 * ticket installation or remove the credentials created in pam_setcred outside
 * of the new session.
 *
 * Returns error codes for pam_setcred, since those are the most granular.  A
 * caller implementing pam_open_session needs to map these (generally by
 * mapping all failures to PAM_SESSION_ERR).
 */
int pamkafs_ticket_set(struct pam_args *args, bool reinitialize) {
    int status;
    const char *user;
    const char *cache;
    struct passwd *pwd;

    /* Don't try to get a token unless we have a K5 ticket cache. */
    cache = pam_getenv(args->pamh, "KRB5CCNAME");
    if (cache == NULL)
        cache = getenv("KRB5CCNAME");
    if (cache == NULL) {
        putil_debug(args, "skipping tokens, no Kerberos ticket cache");
        return PAM_SUCCESS;
    }

    /* Get the user, look them up, and see if we should skip this user. */
    status = pam_get_user(args->pamh, &user, NULL);
    if ((status != PAM_SUCCESS) || (user == NULL)) {
        putil_err_pam(args, status, "no user set");
        return PAM_USER_UNKNOWN;
    }
    pwd = getpwnam(user);
    if (pwd == NULL) {
        putil_err(args, "cannot find UID for %s: %s", user, strerror(errno));
        return PAM_USER_UNKNOWN;
    }
    if (pamkafs_should_ignore(args, pwd)) {
        return PAM_SUCCESS;
    }

    /* Set the Kerberos ticket values into the keyring kda */


    /* Do the work above kda */

    if ((status == PAM_SUCCESS) && !reinitialize) {
        status = pam_set_data(args->pamh, "pam_kafs_session", (char *) "yes", NULL);
        if (status != PAM_SUCCESS) {
            putil_err_pam(args, status, "cannot set success data");
            status = PAM_CRED_ERR;
        }
    }
    if (status == PAM_SUCCESS) {
        maybe_destroy_cache(args, cache);
    }
    return PAM_SUCCESS;
}

/*
 * Delete AFS tickets from the session keyring, but only if our flag data item was
 * set indicating that we'd previously gotten AFS tokens.  Returns either
 * PAM_SUCCESS or PAM_SESSION_ERR.
 */
int pamkafs_tickets_delete(struct pam_args *args) {
    const void *dummy;
    int status;

    /*
     * Do nothing if open_session (or setcred) didn't run.  Otherwise, we may
     * be wiping out some other token that we aren't responsible for.
     */
    if (pam_get_data(args->pamh, "pam_kafs_session", &dummy) != PAM_SUCCESS) {
        putil_debug(args, "skipping, no open session");
        return PAM_SUCCESS;
    }

    /* Okay, go ahead and delete the tokens. */
    putil_debug(args, "Removing tickets from session keyring");
#if 0
    if (k_unlog() != 0) {
        putil_err(args, "unable to delete credentials: %s", strerror(errno));
        return PAM_SESSION_ERR;
    }
#endif

    /*
     * Remove our module data, just in case someone wants to create a new
     * session again later inside the same PAM session.  Just complain but
     * don't fail if we can't delete it, since this is unlikely to cause any
     * significant problems.
     */
    status = pam_set_data(args->pamh, "pam_kafs_session", NULL, NULL);
    if (status != PAM_SUCCESS)
        putil_err_pam(args, status, "unable to remove module data");

    return PAM_SUCCESS;
}
