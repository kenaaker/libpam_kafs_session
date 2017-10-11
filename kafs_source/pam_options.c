/*
 * Option handling for pam-kafs-session.
 *
 * Parses the PAM command line for options to pam-kafs-session and fills out an
 * allocated structure with those details.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010, 2011
 *     The Board of Trustees of the Leland Stanford Junior University
 * Copyright 2017
 *     Ken Aaker
 *
 * See LICENSE for licensing terms.
 */

#include <errno.h>
#include <stdbool.h>
#include <krb5/krb5.h>
#include <string.h>

#include <security/pam_appl.h>

#include "args.h"
#include "logging.h"
#include "options.h"

#include <pam_options.h>

/* Our option definition. */
#define K(name) (#name), offsetof(struct pam_config, name)
static const struct option options[] = {
    { K(afs_cells),          true, LIST    (NULL)       },
    { K(debug),              true, BOOL    (false)      },
    { K(ignore_root),        true, BOOL    (false)      },
    { K(minimum_uid),        true, NUMBER  (0)          },
    { K(retain_after_close), true, BOOL    (false)      }
};
static const size_t optlen = sizeof(options) / sizeof(options[0]);

/*
 * Free the allocated args struct and any memory it points to.
 */
void pamkafs_free(struct pam_args *args) {
    if (args == NULL)
        return;
    if (args->config != NULL) {
        free(args->config);
        args->config = NULL;
    }
    putil_args_free(args);
}


/*
 * Allocate a new struct pam_args and initialize its data members, including
 * parsing the arguments and getting settings from krb5.conf.
 */
struct pam_args *pamkafs_init(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    struct pam_args *args;

    args = putil_args_new(pamh, flags);
    if (args == NULL) {
        return NULL;
    } else {
        args->config = calloc(1, sizeof(struct pam_config));
        if (args->config == NULL) {
            putil_crit(args, "cannot allocate memory: %s", strerror(errno));
            putil_args_free(args);
            args = NULL;
        } else {
            if (!putil_args_defaults(args, options, optlen)) {
                free(args->config);
                putil_args_free(args);
                args = NULL;
            } else {
                if (!putil_args_krb5(args, "pam-kafs-session", options, optlen)) {
                    pamkafs_free(args);
                    args = NULL;
                } else {
                    if (!putil_args_parse(args, argc, argv, options, optlen)) {
                        pamkafs_free(args);
                        args = NULL;
                    } else {
                        if (args->config->debug) {
                            args->debug = true;
                        }
                        /* UIDs are unsigned on some systems. */
                        if (args->config->minimum_uid < 0) {
                            args->config->minimum_uid = 0;
                        }
                    }
                }
            }
        }
    }
    return args;
}

