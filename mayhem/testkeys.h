/* Throwaway ECDSA P-256 code-signing key + self-signed cert (valid until 2126) used by the fuzz harness. */
static const char test_key_pem[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRWanhCA6LXo2dl2s\n"
    "8TUweQSJZyeFeoUGR9bmwG9NsZahRANCAARv6a/UnEersSRt2vGb/Nby7a5otaO2\n"
    "c/3cPSoXaAhh+T9EJs3Q3Ej/jKJZ8c0FtZ/uqHde5JlEIo2UsqJ8L7Mm\n"
    "-----END PRIVATE KEY-----\n";

static const char test_cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIB6DCCAY+gAwIBAgIUFuaYPT4MjIj4lKPqJTGWyyXLloAwCgYIKoZIzj0EAwIw\n"
    "ODEhMB8GA1UEAwwYb3NzbHNpZ25jb2RlIG1heWhlbSB0ZXN0MRMwEQYDVQQKDApz\n"
    "YXZhbnRlbnZzMCAXDTI2MTExNjA4NDAwN1oYDzIxMjYxMDIzMDg0MDA3WjA4MSEw\n"
    "HwYDVQQDDBhvc3Nsc2lnbmNvZGUgbWF5aGVtIHRlc3QxEzARBgNVBAoMCnNhdmFu\n"
    "dGVudnMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARv6a/UnEersSRt2vGb/Nby\n"
    "7a5otaO2c/3cPSoXaAhh+T9EJs3Q3Ej/jKJZ8c0FtZ/uqHde5JlEIo2UsqJ8L7Mm\n"
    "o3UwczAdBgNVHQ4EFgQUWDh6gIFyPaJ+qRzZ3/Hv7v2fKTAwHwYDVR0jBBgwFoAU\n"
    "WDh6gIFyPaJ+qRzZ3/Hv7v2fKTAwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAK\n"
    "BggrBgEFBQcDAzALBgNVHQ8EBAMCB4AwCgYIKoZIzj0EAwIDRwAwRAIgTUO6JBUU\n"
    "sluciBziTyKBGGmxL0Y/JkoKiwBsJGDOmkwCIAEb/7lkgotPLF1wYHkHc+hj4xY9\n"
    "2d0r0LaQu98V1nRy\n"
    "-----END CERTIFICATE-----\n";
