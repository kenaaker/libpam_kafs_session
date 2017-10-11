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

/*
 * The global structure holding our arguments from the PAM configuration.
 * Filled in by pamafs_init.
 */
struct pam_config {
    struct vector *afs_cells;   /* List of AFS cells to get tokens for. */
    bool debug;                 /* Log debugging information. */
    bool ignore_root;           /* Skip authentication for root. */
    bool kdestroy;              /* Destroy ticket cache after aklog. */
    long minimum_uid;           /* Ignore users below this UID. */
    bool retain_after_close;    /* Don't destroy the cache on session end. */
};

/*
 * Free the allocated args struct and any memory it points to.
 */
extern void pamkafs_free(struct pam_args *args);

/*
 * Allocate a new struct pam_args and initialize its data members, including
 * parsing the arguments and getting settings from krb5.conf.
 */
extern struct pam_args *pamkafs_init(pam_handle_t *pamh, int flags, int argc, const char **argv);


