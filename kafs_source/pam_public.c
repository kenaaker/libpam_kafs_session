/*
 * The public APIs of the pam-afs-session PAM module.
 *
 * Provides the public pam_sm_setcred, pam_sm_open_session, and
 * pam_sm_close_session functions, plus whatever other stubs we need to
 * satisfy PAM.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 * Copyright 2006, 2007, 2008, 2010
 *     The Board of Trustees of the Leland Stanford Junior University
 *
 * See LICENSE for licensing terms.
 */

#include <errno.h>
#include <stdbool.h>
#include <krb5/krb5.h>
#include <string.h>
#include <syslog.h>
#include <gcrypt.h>
#include <keyutils.h>
#include <ctype.h>
#include <security/pam_ext.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "args.h"
#include "logging.h"
#include "pam_options.h"
#include "des-mini.h"

#define CREDS_ENCTYPE(c) (c)->keyblock.enctype
#define CREDS_KEYLEN(c) (c)->keyblock.length
#define CREDS_KEYDATA(c) (c)->keyblock.contents

struct rxrpc_key_sec2_v1 {
    uint32_t        kver;                   /* key payload interface version */
    uint16_t        security_index;         /* RxRPC header security index */
    uint16_t        ticket_length;          /* length of ticket[] */
    uint32_t        expiry;                 /* time at which expires */
    uint32_t        kvno;                   /* key version number */
    uint8_t         session_key[8];         /* DES session key */
    uint8_t         ticket[0];              /* the encrypted ticket */
};

#define RXKAD_TKT_TYPE_KERBEROS_V5              256


static void str_to_lower(char *s) {
  char  *p;

  for (p = s; *p != '\0'; ++p) {
    *p = (char)tolower(*p);
  }
}

static void str_to_upper(char *s) {
  char  *p;

  for (p = s; *p != '\0'; ++p) {
    *p = (char)toupper(*p);
  }
}

/*
 * The crypto helper function below were adapted from openafs,
 * but are relicensed as GPL by Chaskiel Grundman, the original author of
 * the relevant patches
 */
static int compress_parity_bits(void *in, void *out, size_t *bytes) {
    size_t i;
    size_t j;
    unsigned char *s;
    unsigned char *sb;
    unsigned char *d;
    unsigned char t;

    if (*bytes % 8) {
        return 1;
    } else {
        s = sb = in;
        sb += 7;
        d = out;

        for (i = 0; i < (*bytes) / 8; ++i) {
            for (j = 0; j < 7; ++j) {
                t = (*s++ & 0xfe);              /* high 7 bits from this byte */
                t |= (*sb >> (j + 1)) & 0x01;   /* low bit is the xth bit of the 8th byte in this group */
                *d++ = t;
            }
            s++;                                /* skip byte used to fill in parity bits */
            sb += 8; /* next block */
        }
        *bytes = d - (unsigned char *)out;
        return 0;
    }
}

static int compute_session_key(void *out, int enctype, size_t keylen, void *keydata) {
    gcry_md_hd_t md;
    unsigned char *mdtmp;
    DES_cblock keytmp;
    int i;
    unsigned char ctr;
    unsigned char L[4];
    char label[] = "rxkad";

    if (gcry_md_open(&md, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC))
        return 1;
    if (gcry_md_setkey(md, keydata, keylen)) {
        gcry_md_close(md);
        return 1;
    }
    L[0]=0;
    L[1]=0;
    L[2]=0;
    L[3]=64;
    for (i=1; i< 256; i++) {
        ctr=i & 0xFF;
        gcry_md_write(md, &ctr, 1);
        gcry_md_write(md, label, strlen(label)+1); /* write the null too */
        gcry_md_write(md, L, 4);
        mdtmp=gcry_md_read(md, 0);
        if (!mdtmp) {
            gcry_md_close(md);
            return 1;
        }
        memcpy(keytmp, mdtmp, DES_CBLOCK_LEN);
        DES_set_odd_parity(&keytmp);
        if (!DES_is_weak_key(&keytmp)) {
            memcpy(out, keytmp, DES_CBLOCK_LEN);
            gcry_md_close(md);
            return 0;
        }
        gcry_md_reset(md);
    }
    gcry_md_close(md);
    return 1;
}

static int convert_key(void *out, int enctype, size_t keylen,
                       void *keydata) {
    char tdesbuf[24];

    switch (enctype) {
    case ENCTYPE_DES_CBC_CRC:
    case ENCTYPE_DES_CBC_MD4:
    case ENCTYPE_DES_CBC_MD5:
        if (keylen != 8)
            return 1;

        /* Extract session key */
        memcpy(out, keydata, 8);
        break;
    case ENCTYPE_NULL:
    case 4:
    case 6:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
        return 1;
        /*In order to become a "Cryptographic Key" as specified in
     * SP800-108, it must be indistinguishable from a random bitstring. */
    case 5:
    case 7:
    case ENCTYPE_DES3_CBC_SHA1:
        if (keylen > 24)
            return 1;
        if (compress_parity_bits(keydata, tdesbuf, &keylen))
            return 1;
        keydata=tdesbuf;
        /* FALLTHROUGH */
    default:
        if (enctype < 0)
            return 1;
        if (keylen < 7)
            return 1;
        return compute_session_key(out, enctype, keylen, keydata);
    }
    return 0;
}

static bool set_afs_krb5_ticket(struct pam_args *args) {
    krb5_context k5_ctx;
    krb5_error_code kresult;
    bool ret_value;

    kresult=krb5_init_context(&k5_ctx);
    if (kresult) {
        putil_err(args, "krb5_init_context failed\n");
        ret_value = false;
    } else {
        krb5_ccache cc;
        krb5_creds search_cred = {0};
        krb5_creds *creds = NULL;
        struct rxrpc_key_sec2_v1 *payload;
        key_serial_t dest_keyring;
        key_serial_t sessring;
        key_serial_t usessring;
        key_serial_t ret;
        char description[256];
        char *realm = NULL;
        char *cell = NULL;
        const char *krb5ccname = NULL;
        int mode;
        size_t plen;

        putil_notice(args, "Getting ready to add to keyring.");
        krb5_get_default_realm(k5_ctx, &realm);
        putil_notice(args, "Kerberos default realm is \"%s\".", realm);
        cell = strndup(realm, MAX_KEYTAB_NAME_LEN);
        str_to_lower(cell);
        putil_notice(args, "Kerberos cell is \"%s\".", cell);

        kresult = krb5_allow_weak_crypto(k5_ctx, 1);
        krb5ccname = pam_getenv(args->pamh, "KRB5CCNAME");
        putil_notice(args, "KRB5CCNAME=\"%s\".", krb5ccname);
        if (krb5ccname == NULL) {
            ret_value = false;
        } else {
            kresult = krb5_cc_set_default_name(k5_ctx, krb5ccname);
            putil_notice(args, "cc_set_default_name Kerberos kresult is %d.", kresult);
            kresult = krb5_cc_default(k5_ctx, &cc);

            memset(&search_cred, 0, sizeof(krb5_creds));
            kresult = krb5_cc_get_principal(k5_ctx, cc, &search_cred.client);
            putil_notice(args, "cc_get_principal Kerberos kresult is %d string is \"%s\".", kresult,
                         krb5_get_error_message(k5_ctx, kresult));

            for (mode = 0; mode < 2; ++mode) {
                putil_debug(args, "Building server principal name.");
                kresult = krb5_build_principal(k5_ctx, &search_cred.server,
                                               strlen(realm), realm, "afs",
                                               mode ? NULL : cell, NULL);
                putil_notice(args, "build_principal Kerberos kresult is %d.", kresult);
                kresult = krb5_get_credentials(k5_ctx, 0, cc, &search_cred, &creds);
                putil_notice(args, "get_credentials Kerberos kresult is %d string is \"%s\".",
                             kresult, krb5_get_error_message(k5_ctx, kresult));
                if (kresult == 0) {
                    ret_value = true;
                    break;
                } else {
                    putil_notice(args, "krb5_get_credentials failed, doing free_principal.");
                    krb5_free_principal(k5_ctx, search_cred.server);
                    putil_notice(args, "krb5_free_principal returned.");
                    search_cred.server = NULL;
                }
            }
            putil_debug(args, "Getting tickets");
            plen = sizeof(*payload) + creds->ticket.length;
            payload = calloc(1, plen + 4);
            if (payload == NULL) {
                putil_err(args, "%s:%d Failed to calloc payload area.", __func__, __LINE__);
                ret_value = false;
            } else {
                /* use version 1 of the key data interface */
                payload->kver = 1;
                payload->security_index = 2;
                payload->ticket_length = creds->ticket.length;
                payload->expiry = creds->times.endtime;
                payload->kvno = RXKAD_TKT_TYPE_KERBEROS_V5;
                if (convert_key(payload->session_key, CREDS_ENCTYPE(creds),
                                CREDS_KEYLEN(creds), CREDS_KEYDATA(creds))) {
                    putil_err(args, "session key could not be converted to a suitable DES key\n");
                    ret_value = false;
                } else {
                    memcpy(payload->ticket, creds->ticket.data, creds->ticket.length);

                    /*
                     * If the session keyring is not set (i.e. using the uid session keyring),
                     * then the kernel will instantiate a new session keyring if any keys are
                     * added to KEY_SPEC_SESSION_KEYRING! Since we exit immediately, that
                     * keyring will be orphaned. So, add the key to KEY_SPEC_USER_SESSION_KEYRING
                     * in that case
                     */
                    dest_keyring = KEY_SPEC_SESSION_KEYRING;
                    sessring = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
                    usessring = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);
                    if (sessring == usessring) {
                        dest_keyring = KEY_SPEC_USER_SESSION_KEYRING;
                    }
                    snprintf(description, 255, "afs@%s", cell);
                    str_to_upper(&description[4]);

                    ret = add_key("rxrpc", description, payload, plen, dest_keyring);
                    putil_debug(args, "Done adding to keyring.");
                    krb5_free_creds(k5_ctx, creds);
                    krb5_free_cred_contents(k5_ctx, &search_cred);
                    krb5_cc_close(k5_ctx, cc);
                    if (realm != NULL ) {
                        krb5_free_default_realm(k5_ctx, realm);
                    }
                    ret_value = true;
                }
            }
        }
        krb5_free_context(k5_ctx);
    }
    return ret_value;
}


/*
 * Open a new session. A Kerberos PAM module should have previously run to
 * obtain Kerberos tickets (or ticket forwarding should have already
 * happened).
 */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    struct pam_args *args;
    int pamret = PAM_SUCCESS;
    const char *pam_user;

    args = pamkafs_init(pamh, flags, argc, argv);
    if (args == NULL) {
        pamret = PAM_SESSION_ERR;
    } else {
        ENTRY(args, flags);
        pamret = pam_get_user(pamh, &pam_user, NULL);
        putil_notice(args, "%s:%d args->config->ignore_root=%d, pam_user=\"%s\" pamret=%d",
                     __func__, __LINE__, args->config->ignore_root, pam_user, pamret);
        if ((args->config->ignore_root) &&
            ((pam_user == NULL) || (strcmp("root", pam_user) == 0))) {
            pamret = PAM_SUCCESS;
            putil_notice(args, "%s:%d Ignoring root", __func__, __LINE__);
        } else {
            putil_notice(args, "%s:%d Here", __func__, __LINE__);
            if (set_afs_krb5_ticket(args)) {
                pamret = PAM_SUCCESS;
                putil_notice(args, "%s:%d Here", __func__, __LINE__);
            } else {
                pamret = PAM_SESSION_ERR;
                putil_notice(args, "%s:%d Here", __func__, __LINE__);
            }
            putil_notice(args, "%s:%d Here", __func__, __LINE__);
        }
        EXIT(args, pamret);
        pamkafs_free(args);
    }
    return pamret;
}

/*
 * Don't do anything for authenticate.  We're only an auth module so that we
 * can supply a pam_setcred implementation.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    struct pam_args *args;
    int pamret;

    /*
     * We want to return PAM_IGNORE here, but Linux PAM 0.99.7.1 (at least)
     * has a bug that causes PAM_IGNORE to result in authentication failure
     * when the module is marked [default=done].  So we return PAM_SUCCESS,
     * which is dangerous but works in that case.
     */
    args = pamkafs_init(pamh, flags, argc, argv);
    if (args == NULL) {
        pamret = PAM_CRED_ERR;
    } else {
        ENTRY(args, flags);
        pamret = PAM_SUCCESS;
        EXIT(args, pamret);
        pamkafs_free(args);
    }
    return pamret;
}


/*
 * Calling pam_setcred with PAM_ESTABLISH_CRED is equivalent to opening a new
 * session for our purposes.  With PAM_REFRESH_CRED, we don't call setpag,
 * just run aklog again.  PAM_DELETE_CRED calls unlog.
 */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
    struct pam_args *args;
    int status;
    int pamret = PAM_SUCCESS;
    const void *dummy;
    bool reinitialize;

    args = pamkafs_init(pamh, flags, argc, argv);
    if (args == NULL) {
        pamret = PAM_CRED_ERR;
        return pamret;
    } else {
        putil_notice(args, "Just Starting.");
        ENTRY(args, flags);

        /*
     * If DELETE_CRED was specified, delete the tickets (if any).  Similarly
     * return PAM_SUCCESS here instead of PAM_IGNORE.  Map the error code for
     * pam_setcred, since normally this call is made by pam_close_session.
     */
        if (flags & PAM_DELETE_CRED) {
            if (args->config->retain_after_close) {
                putil_debug(args, "skipping as configured");
                pamret = PAM_SUCCESS;
            } else {
#if 0
                pamret = pamkafs_token_delete(args);
#endif
                if (pamret == PAM_SESSION_ERR) {
                    pamret = PAM_CRED_ERR;
                }
            }
        } else {
            const char *pam_user;
            pamret = pam_get_user(pamh, &pam_user, NULL);
            putil_notice(args, "args->config->ignore_root=%d, user=\"%s\"", args->config->ignore_root, pam_user);
            if ((args->config->ignore_root) &&
                ((pam_user == NULL) || (strcmp("root", pam_user) == 0))) {
                pamret = PAM_SUCCESS;
                putil_notice(args, "Ignoring root user");
            } else {
                /*
                 * We're acquiring tokens.  See if we already have done this and don't do
                 * it again if we have unless we were explicitly told to reinitialize.  If
                 * we're reinitializing, we may be running in a screen saver or the like.
                 */
                reinitialize = (flags & (PAM_REINITIALIZE_CRED | PAM_REFRESH_CRED));
                putil_notice(args, "reinitialize=%d", reinitialize);
                if (!reinitialize) {
                    status = pam_get_data(pamh, "pam_kafs_session", &dummy);
                    if (status != PAM_SUCCESS) {
                        if (set_afs_krb5_ticket(args)) {
                            pamret = PAM_SUCCESS;
                        } else {
                            pamret = PAM_SESSION_ERR;
                        }
                    } else {
                        putil_debug(args, "skipping, apparently already ran");
                    }
                }
            }
        }
        EXIT(args, pamret);
        pamkafs_free(args);
    }
    return pamret;
}


/*
 * Close a session.  Normally, what we do here is call unlog, but we can be
 * configured not to do so.
 */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                         const char *argv[]) {
    struct pam_args *args;
    int pamret = PAM_SUCCESS;

    args = pamkafs_init(pamh, flags, argc, argv);
    if (args == NULL) {
        pamret = PAM_SESSION_ERR;
    } else {
        ENTRY(args, flags);
        /* Do nothing if so configured. */
        if (args->config->retain_after_close) {
            putil_debug(args, "skipping as configured");
            pamret = PAM_IGNORE;
        } else {
            /* Delete tokens. */
#if 0
            pamret = pamkafs_token_delete(args);
#endif
        }
        EXIT(args, pamret);
        pamkafs_free(args);
    }
    return pamret;
}
