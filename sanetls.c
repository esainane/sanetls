/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <stdio.h>

#include <openssl/ssl.h>

#include <stdlib.h>
#include <dlfcn.h>

/*
 * Configuration from interposed environment
 */

static const char *dhparams_file = 0;
static const char *forced_ciphers = 0;
static const char *forced_options = 0;
static const char *forced_clearoptions = 0;
static long forced_option_bits = 0;
static long forced_clearoption_bits = 0;
static int init = 0;

static long parse_or_default(const char *str, long def) {
  long ret;
  if (str) {
    char *end;
    ret = strtol(str, &end, 0);
    if (str != end) {
      return ret;
    }
  }
  return def;
}

static void setup(void) {
  dhparams_file = secure_getenv("DHPARAMS_FILE");
  forced_ciphers = secure_getenv("FORCED_CIPHERS");
  forced_options = secure_getenv("FORCED_OPTIONS");
  forced_option_bits = parse_or_default(forced_options, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_SINGLE_DH_USE);
  forced_clearoptions =  secure_getenv("FORCED_CLEAROPTIONS");
  forced_clearoption_bits = parse_or_default(forced_clearoptions, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  init = 1;
}

static long get_forced_option_bits(void) {
  if (!init) setup();
  return forced_option_bits;
}

static long get_forced_clearoption_bits(void) {
  if (!init) setup();
  return forced_clearoption_bits;
}

static const char *get_dhparams_file(void) {
  if (!init) setup();
  return dhparams_file;
}

static const char *get_forced_ciphers(void) {
  if (!init) setup();
  return forced_ciphers;
}

static DH *get_DH() {
  static int done = 0;
  static DH *dh = 0;
  if (done) return dh;
  FILE *dhfile = fopen(get_dhparams_file(), "r");
  if (!dhfile) {
    fprintf(stderr, "Unable to open DH params file '%s'!\n", get_dhparams_file());
    return 0;
  }
  dh = PEM_read_DHparams(dhfile, 0, 0, 0);
  fclose(dhfile);
  done = 1;
  if (!dh) {
    fprintf(stderr, "Unable to parse DH params file '%s'!\n", get_dhparams_file());
  }
  return dh; /* Might still be 0 if an error occurred */
}

static DH *injected_callback(SSL *SSL, int is_export, int keylength) {
  /*
   * If we get here, utterly ignore is_export and keylength:
   * "Previous versions of the callback used is_export and keylength parameters
   *  to control parameter generation for export and non-export cipher suites.
   *  Modern servers that do not support export ciphersuites are advised to
   *  either use SSL_CTX_set_tmp_dh() or alternatively, use the callback but
   *  ignore keylength and is_export and simply supply at least 2048-bit
   *  parameters in the callback."
   * - OpenSSL manual, https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_tmp_dh_callback.html
   */
  return get_DH();
}

/*
 * Begin interposing functionality
 */

/* Not a macro on reference system */
#ifdef SSL_CTX_new
#error SSL_CTX_new is a macro!
#undef SSL_CTX_new
#endif

/* Not currently required: We have ensured will always inherit a sane context.
 * Functions that manipulate the SSL entity directly are overridden later. */
/* SSL *SSL_new(SSL_CTX *ctx); */

/* Hook into the creation of new contexts. In the event that an application
 * performs absolutely no configuration, we still set sane defaults. */
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
  static SSL_CTX *(*SSL_CTX_new_real)(const SSL_METHOD *method) = 0;
  if (!SSL_CTX_new_real)
    SSL_CTX_new_real = dlsym(RTLD_NEXT, "SSL_CTX_new");
  SSL_CTX *ret = SSL_CTX_new_real(method);
  /* Dispatch to our overridden methods, which may or may not be macros */
  if (get_forced_clearoption_bits()) {
    SSL_CTX_clear_options(ret, 0);
  }
  if (get_forced_option_bits()) {
    SSL_CTX_set_options(ret, 0);
  }

  if (get_dhparams_file()) {
    SSL_CTX_set_tmp_dh(ret, get_DH());
  }
  if (get_forced_ciphers()) {
    SSL_CTX_set_cipher_list(ret, get_forced_ciphers());
  }
  return ret;
}

/* Protocol overrides. */

#ifdef SSL_CTX_clear_options
/* Handled case in SSL_CTX_ctrl */
// #warning SSL_CTX_clear_options is a macro!
#undef SSL_CTX_clear_options
#endif

long SSL_CTX_clear_options(SSL_CTX *ctx, long options) {
  static long (*SSL_CTX_clear_options_real)(SSL_CTX *ctx, long options) = 0;
  if (!SSL_CTX_clear_options_real)
    SSL_CTX_clear_options_real = dlsym(RTLD_NEXT, "SSL_CTX_clear_options");
  return SSL_CTX_clear_options_real(ctx, (options | get_forced_clearoption_bits()) & ~get_forced_option_bits());
}

#ifdef SSL_clear_options
/* Handled case in SSL_ctrl */
// #warning SSL_clear_options is a macro!
#undef SSL_clear_options
#endif

long SSL_clear_options(SSL *ssl, long options) {
  static long (*SSL_clear_options_real)(SSL *ssl, long options) = 0;
  if (!SSL_clear_options_real)
    SSL_clear_options_real = dlsym(RTLD_NEXT, "SSL_clear_options");
  return  SSL_clear_options_real(ssl, (options | get_forced_clearoption_bits()) & ~get_forced_option_bits());
}

#ifdef SSL_CTX_set_options
/* Handled case in SSL_CTX_ctrl */
// #warning SSL_CTX_set_options is a macro!
#undef SSL_CTX_set_options
#endif

long SSL_CTX_set_options(SSL_CTX *ctx, long options) {
  static long (*SSL_CTX_set_options_real)(SSL_CTX *ctx, long options) = 0;
  if (!SSL_CTX_set_options_real)
    SSL_CTX_set_options_real = dlsym(RTLD_NEXT, "SSL_CTX_set_options");
  return SSL_CTX_set_options_real(ctx, (options & ~get_forced_clearoption_bits()) | get_forced_option_bits());
}

#ifdef SSL_set_options
/* Handled case in SSL_ctrl */
// #warning SSL_set_options is a macro!
#undef SSL_set_options
#endif

long SSL_set_options(SSL *ssl, long options) {
  static long (*SSL_set_options_real)(SSL *ssl, long options) = 0;
  if (!SSL_set_options_real)
    SSL_set_options_real = dlsym(RTLD_NEXT, "SSL_set_options");
  return SSL_set_options_real(ssl, (options & ~get_forced_clearoption_bits()) | get_forced_option_bits());
}

/* DHPARAM overrides. */

/* Not a macro on reference system */
#ifdef SSL_CTX_set_tmp_dh_callback
#error SSL_CTX_set_tmp_dh_callback is a macro!
#undef SSL_CTX_set_tmp_dh_callback
#endif

void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
          DH *(*tmp_dh_callback)(SSL *ssl, int is_export, int keylength)) {
  static void (*SSL_CTX_set_tmp_dh_callback_real)(SSL_CTX *ctx,
          DH *(*tmp_dh_callback)(SSL *ssl, int is_export, int keylength)) = 0;
  if (!SSL_CTX_set_tmp_dh_callback_real)
    SSL_CTX_set_tmp_dh_callback_real = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh_callback");
  SSL_CTX_set_tmp_dh_callback_real(ctx, injected_callback);
}

#ifdef SSL_CTX_set_tmp_dh
/* Handled in SSL_CTX_ctrl */
// #warning SSL_CTX_set_tmp_dh is a macro!
#undef SSL_CTX_set_tmp_dh
#endif

long SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh) {
  static long (*SSL_CTX_set_tmp_dh_real)(SSL_CTX *ctx, DH *dh) = 0;
  if (!SSL_CTX_set_tmp_dh_real)
    SSL_CTX_set_tmp_dh_real = dlsym(RTLD_NEXT, "SSL_CTX_set_tmp_dh");
  DH *our_dh = get_DH();
  if (our_dh) dh = our_dh;
  return SSL_CTX_set_tmp_dh_real(ctx, dh);
}

/* Not a macro on reference system */
#ifdef SSL_set_tmp_dh_callback
#error SSL_set_tmp_dh_callback is a macro!
#undef SSL_set_tmp_dh_callback
#endif

void SSL_set_tmp_dh_callback(SSL *ctx /* sic, see https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_tmp_dh_callback.html */,
          DH *(*tmp_dh_callback)(SSL *ssl, int is_export, int keylength)) {
  static void (*SSL_set_tmp_dh_callback_real)(SSL *ctx,
          DH *(*tmp_dh_callback)(SSL *ssl, int is_export, int keylength)) = 0;
  if (!SSL_set_tmp_dh_callback_real)
    SSL_set_tmp_dh_callback_real = dlsym(RTLD_NEXT, "SSL_set_tmp_dh_callback");
  SSL_set_tmp_dh_callback_real(ctx, injected_callback);
}

/* Macro on reference system! */
#ifdef SSL_set_tmp_dh
/* Handled case in SSL_ctrl */
// #warning SSL_set_tmp_dh is a macro!
#undef SSL_set_tmp_dh
#endif

long SSL_set_tmp_dh(SSL *ssl, DH *dh) {
  static long (*SSL_set_tmp_dh_real)(SSL *ssl, DH *dh) = 0;
  if (!SSL_set_tmp_dh_real)
    SSL_set_tmp_dh_real = dlsym(RTLD_NEXT, "SSL_set_tmp_dh");
  DH *our_dh = get_DH();
  if (our_dh) dh = our_dh;
  return SSL_set_tmp_dh_real(ssl, dh);
}

/* Ciphers overrides. */

/* Not a macro on reference system */
#ifdef SSL_CTX_set_cipher_list
#error SSL_CTX_set_cipher_list is a macro!
#undef SSL_CTX_set_cipher_list
#endif

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
  static int (*SSL_CTX_set_cipher_list_real)(SSL_CTX *ctx, const char *str) = 0;
  if (!SSL_CTX_set_cipher_list_real)
    SSL_CTX_set_cipher_list_real = dlsym(RTLD_NEXT, "SSL_CTX_set_cipher_list");
  return SSL_CTX_set_cipher_list_real(ctx, get_forced_ciphers() ? get_forced_ciphers() : str);
}

/* Not a macro on reference system */
#ifdef SSL_set_cipher_list
#error SSL_set_cipher_list is a macro!
#undef SSL_set_cipher_list
#endif

int SSL_set_cipher_list(SSL *ssl, const char *str) {
  static int (*SSL_set_cipher_list_real)(SSL *ssl, const char *str) = 0;
  if (!SSL_set_cipher_list_real)
    SSL_set_cipher_list_real = dlsym(RTLD_NEXT, "SSL_set_cipher_list");
  return SSL_set_cipher_list_real(ssl, get_forced_ciphers() ? get_forced_ciphers() : str);
}

/*
 * Begin interposing around internal functions where "function calls" are macros in practice
 */

/* OpenSSL has too much not documented as a macro. These are the internal functions the macros dispatch to. */

/* Not a macro on reference system */
#ifdef SSL_CTX_ctrl
#error SSL_CTX_ctrl is a macro!
#undef SSL_CTX_ctrl
#endif

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {
  static long (*SSL_CTX_ctrl_real)(SSL_CTX *ctx, int cmd, long larg, void *parg) = 0;
  if (!SSL_CTX_ctrl_real)
    SSL_CTX_ctrl_real = dlsym(RTLD_NEXT, "SSL_CTX_ctrl");
  switch(cmd) {
    /* Only tweak parameters for the functions we are concerned with. */
  case SSL_CTRL_CLEAR_OPTIONS:
    larg &= ~get_forced_option_bits();
    break;
  case SSL_CTRL_OPTIONS:
    larg |= get_forced_option_bits();
    break;
  case SSL_CTRL_SET_TMP_DH: {
      DH *our_dh = get_DH();
      if (our_dh) parg = our_dh;
      break;
    }
  default:
    break;
  }
  return SSL_CTX_ctrl_real(ctx, cmd, larg, parg);
}

/* Not a macro on reference system */
#ifdef SSL_ctrl
#error SSL_ctrl is a macro!
#undef SSL_ctrl
#endif

long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg) {
  static long (*SSL_ctrl_real)(SSL *ssl, int cmd, long larg, void *parg) = 0;
  if (!SSL_ctrl_real)
    SSL_ctrl_real = dlsym(RTLD_NEXT, "SSL_ctrl");
  switch(cmd) {
    /* Only tweak parameters for the functions we are concerned with. */
  case SSL_CTRL_CLEAR_OPTIONS:
    larg &= ~get_forced_option_bits();
    break;
  case SSL_CTRL_OPTIONS:
    larg |= get_forced_option_bits();
    break;
  case SSL_CTRL_SET_TMP_DH: {
      DH *our_dh = get_DH();
      if (our_dh) parg = our_dh;
      break;
    }
  default:
    break;
  }
  return SSL_ctrl_real(ssl, cmd, larg, parg);
}
