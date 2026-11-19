/*
 * In-process fuzz harness for osslsigncode's file-format parsers and Authenticode signature code.
 *
 * upstream's main() is a CLI that reports failures with `goto err_cleanup` (never exit()), and
 * main_execute() frees everything it allocated. This harness includes osslsigncode.c to reach the
 * static main_execute(), runs one CLI command per input against a scratch file, and returns.
 * One-time OpenSSL/OID setup (main()'s prologue) happens in LLVMFuzzerInitialize.
 *
 * Built once per target with -DFUZZ_MODE=<FUZZ_VERIFY|FUZZ_EXTRACT|FUZZ_SIGN|FUZZ_SCRIPT|FUZZ_ATTACH>.
 *   verify   osslsigncode verify -in <input>                      (PE / MSI / CAB / APPX / CAT)
 *   extract  extract-signature, then remove-signature on <input>  (same formats)
 *   sign     sign (plain + page hashes via -ph), then sign -nest on <input>
 *   script   data[0] picks extension (8 script types) and command (verify/sign/remove/extract)
 *   attach   attach-signature -sigin <input as PKCS#7> on a fixed unsigned .ps1
 * Network access is disabled (-ignore-cdp); stdout is silenced because the CLI prints a lot.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FUZZ_VERIFY  1
#define FUZZ_EXTRACT 2
#define FUZZ_SIGN    3
#define FUZZ_SCRIPT  4
#define FUZZ_ATTACH  5

#ifndef FUZZ_MODE
#error "define FUZZ_MODE"
#endif

#define main osslsigncode_main
#include "osslsigncode.c"
#undef main

#include "testkeys.h"

static char dir[512], in_bin[600], in_ps1[600], sig_file[600], out_file[600], cert_file[600], key_file[600];

static const char *const script_ext[8] = {
    ".ps1", ".ps1xml", ".psc1", ".psd1", ".psm1", ".cdxml", ".mof", ".js"
};

static const char attach_target[] = "Write-Host \"hello\"\r\n";

static ssize_t discard_write(void *cookie, const char *buf, size_t size)
{
    (void)cookie;
    (void)buf;
    return (ssize_t)size;
}

static int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");

    if (!f)
        return 0;
    if (len && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return 0;
    }
    return fclose(f) == 0;
}

static void cleanup_dir(void)
{
    const char *files[] = { in_bin, in_ps1, sig_file, out_file, cert_file, key_file };
    size_t i;

    for (i = 0; i < sizeof files / sizeof *files; i++)
        unlink(files[i]);
    rmdir(dir);
}

static void run(int argc, char **argv)
{
    unlink(out_file);
    (void)main_execute(argc, argv);
    unlink(out_file);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    const char *tmp = getenv("TMPDIR");

    (void)argc;
    (void)argv;
    if (!tmp || !*tmp)
        tmp = "/tmp";
    snprintf(dir, sizeof dir, "%s/osslsigncode-fuzz-XXXXXX", tmp);
    if (!mkdtemp(dir))
        abort();
    snprintf(in_bin, sizeof in_bin, "%s/input.bin", dir);
    snprintf(in_ps1, sizeof in_ps1, "%s/target.ps1", dir);
    snprintf(sig_file, sizeof sig_file, "%s/sig.p7", dir);
    snprintf(out_file, sizeof out_file, "%s/out", dir);
    snprintf(cert_file, sizeof cert_file, "%s/cert.pem", dir);
    snprintf(key_file, sizeof key_file, "%s/key.pem", dir);
    atexit(cleanup_dir);
    if (!write_file(cert_file, test_cert_pem, sizeof test_cert_pem - 1)
        || !write_file(key_file, test_key_pem, sizeof test_key_pem - 1)
        || !write_file(in_ps1, attach_target, sizeof attach_target - 1))
        abort();

    /* the CLI's console output is not what is being tested */
    stdout = fopencookie(NULL, "w", (cookie_io_functions_t){ .write = discard_write });
    if (!stdout)
        abort();

    /* main()'s one-time setup */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS
        | OPENSSL_INIT_ADD_ALL_CIPHERS
        | OPENSSL_INIT_ADD_ALL_DIGESTS
        | OPENSSL_INIT_LOAD_CONFIG, NULL))
        abort();
    if (!OBJ_create(SPC_STATEMENT_TYPE_OBJID, NULL, NULL)
        || !OBJ_create(MS_JAVA_SOMETHING, NULL, NULL)
        || !OBJ_create(SPC_SP_OPUS_INFO_OBJID, NULL, NULL)
        || !OBJ_create(SPC_NESTED_SIGNATURE_OBJID, NULL, NULL)
        || !OBJ_create(SPC_UNAUTHENTICATED_DATA_BLOB_OBJID, NULL, NULL)
        || !OBJ_create(SPC_RFC3161_OBJID, NULL, NULL)
        || !OBJ_create(PKCS9_SEQUENCE_NUMBER, NULL, NULL))
        abort();
    ui_method = ui_osslsigncode();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#if FUZZ_MODE == FUZZ_SCRIPT
    char path[700];
    char *sv[] = { "osslsigncode", "verify", "-ignore-cdp", "-CAfile", cert_file, "-in", path, NULL };
    char *ss[] = { "osslsigncode", "sign", "-certs", cert_file, "-key", key_file, "-in", path,
        "-out", out_file, NULL };
    char *sr[] = { "osslsigncode", "remove-signature", "-in", path, "-out", out_file, NULL };
    char *se[] = { "osslsigncode", "extract-signature", "-in", path, "-out", out_file, NULL };
    char **sc[4] = { sv, ss, sr, se };
    const int sn[4] = { 7, 10, 6, 6 };
    unsigned sel;

    /* script_ctx_new() (script.c) returns NULL for an empty file; a lone selector byte is such a file. */
    if (size < 2)
        return -1;
    sel = data[0];
    snprintf(path, sizeof path, "%s/input%s", dir, script_ext[sel & 7]);
    if (!write_file(path, data + 1, size - 1))
        abort();
    run(sn[(sel >> 3) & 3], sc[(sel >> 3) & 3]);
    unlink(path);
#elif FUZZ_MODE == FUZZ_ATTACH
    char *a1[] = { "osslsigncode", "attach-signature", "-sigin", sig_file, "-in", in_ps1,
        "-out", out_file, NULL };

    if (!write_file(sig_file, data, size))
        abort();
    run(8, a1);
#elif FUZZ_MODE == FUZZ_VERIFY
    char *v1[] = { "osslsigncode", "verify", "-ignore-cdp", "-CAfile", cert_file, "-in", in_bin, NULL };

    if (!write_file(in_bin, data, size))
        abort();
    run(7, v1);
#elif FUZZ_MODE == FUZZ_EXTRACT
    char *e1[] = { "osslsigncode", "extract-signature", "-in", in_bin, "-out", out_file, NULL };
    char *e2[] = { "osslsigncode", "remove-signature", "-in", in_bin, "-out", out_file, NULL };

    if (!write_file(in_bin, data, size))
        abort();
    run(6, e1);
    run(6, e2);
#elif FUZZ_MODE == FUZZ_SIGN
    char *s1[] = { "osslsigncode", "sign", "-certs", cert_file, "-key", key_file, "-ph",
        "-add-msi-dse", "-in", in_bin, "-out", out_file, NULL };
    char *s2[] = { "osslsigncode", "sign", "-certs", cert_file, "-key", key_file, "-nest",
        "-in", in_bin, "-out", out_file, NULL };

    if (!write_file(in_bin, data, size))
        abort();
    run(12, s1);
    run(11, s2);
#endif
    return 0;
}
