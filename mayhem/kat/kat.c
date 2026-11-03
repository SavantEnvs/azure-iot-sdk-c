// Known-answer probe for the SDK's c-utility primitives and the IoT Hub message/connection-string APIs.
// Built with the project's normal flags by build.sh; run by test.sh. Prints "PASS <name>" / "FAIL <name>".
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "azure_c_shared_utility/azure_base64.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/hmacsha256.h"
#include "azure_c_shared_utility/map.h"
#include "azure_c_shared_utility/sastoken.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/urlencode.h"
#include "azure_c_shared_utility/xio.h"
#include "iothub.h"
#include "iothub_message.h"

// The SDK is configured without a TLS adapter; platform_linux.c references this one. Never called here.
const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void)
{
    return NULL;
}

static int failures = 0;

static void check(const char* name, int ok)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

static int str_is(STRING_HANDLE h, const char* expected)
{
    int ok = (h != NULL) && strcmp(STRING_c_str(h), expected) == 0;
    if (!ok) printf("  got: %s\n  want: %s\n", h ? STRING_c_str(h) : "(null)", expected);
    STRING_delete(h);
    return ok;
}

int main(void)
{
    (void)IoTHub_Init();
    // Base64 (RFC 4648 vectors)
    check("base64_encode_foobar", str_is(Azure_Base64_Encode_Bytes((const unsigned char*)"foobar", 6), "Zm9vYmFy"));
    check("base64_encode_fo", str_is(Azure_Base64_Encode_Bytes((const unsigned char*)"fo", 2), "Zm8="));
    check("base64_encode_f", str_is(Azure_Base64_Encode_Bytes((const unsigned char*)"f", 1), "Zg=="));
    {
        BUFFER_HANDLE b = Azure_Base64_Decode("Zm9vYmE=");
        check("base64_decode_fooba", b != NULL && BUFFER_length(b) == 5 && memcmp(BUFFER_u_char(b), "fooba", 5) == 0);
        BUFFER_delete(b);
        check("base64_decode_rejects_bad_length", Azure_Base64_Decode("Zm9vY") == NULL);
    }

    // HMAC-SHA256, RFC 4231 test case 2
    {
        static const unsigned char want[32] = {
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
            0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43 };
        BUFFER_HANDLE h = BUFFER_new();
        const char* msg = "what do ya want for nothing?";
        int rc = HMACSHA256_ComputeHash((const unsigned char*)"Jefe", 4, (const unsigned char*)msg, strlen(msg), h);
        check("hmac_sha256_rfc4231_2", rc == HMACSHA256_OK && BUFFER_length(h) == 32 && memcmp(BUFFER_u_char(h), want, 32) == 0);
        BUFFER_delete(h);
    }

    // URL encoding (the SDK emits lowercase hex digits)
    check("url_encode", str_is(URL_EncodeString("a b/c"), "a%20b%2fc"));
    check("url_decode", str_is(URL_DecodeString("a%20b%2Fc"), "a b/c"));

    // SAS token: expected value computed independently with python hmac/hashlib
    check("sas_token_with_key_name", str_is(
        SASToken_CreateString("c2VjcmV0a2V5MTIzNA==", "myhub.azure-devices.net%2Fdevices%2Fdev1", "dev1key", 1700000000ULL),
        "SharedAccessSignature sr=myhub.azure-devices.net%2Fdevices%2Fdev1&sig=lJPYnwdjCxsz675sBxa1lmXfbjAPDho8WDxDgF5RWvY%3d&se=1700000000&skn=dev1key"));
    check("sas_token_without_key_name", str_is(
        SASToken_CreateString("c2VjcmV0a2V5MTIzNA==", "myhub.azure-devices.net%2Fdevices%2Fdev1", NULL, 1700000000ULL),
        "SharedAccessSignature sr=myhub.azure-devices.net%2Fdevices%2Fdev1&sig=lJPYnwdjCxsz675sBxa1lmXfbjAPDho8WDxDgF5RWvY%3d&se=1700000000"));
    check("sas_token_bad_key", SASToken_CreateString("not base64!", "scope", NULL, 1ULL) == NULL);
    {
        STRING_HANDLE t = SASToken_CreateString("c2VjcmV0a2V5MTIzNA==", "scope", NULL, 4102444800ULL);
        check("sas_token_validate_accepts_own_token", t != NULL && SASToken_Validate(t));
        STRING_delete(t);
        STRING_HANDLE bad = STRING_construct("SharedAccessSignature sr=scope&sig=abc");
        check("sas_token_validate_rejects_missing_se", !SASToken_Validate(bad));
        STRING_delete(bad);
    }

    // STRING
    {
        STRING_HANDLE s = STRING_construct("abc");
        STRING_concat(s, "def");
        check("string_concat", s != NULL && STRING_length(s) == 6 && strcmp(STRING_c_str(s), "abcdef") == 0);
        STRING_replace(s, 'c', 'X');
        check("string_replace", strcmp(STRING_c_str(s), "abXdef") == 0);
        STRING_delete(s);
    }

    // IoT Hub message properties
    {
        IOTHUB_MESSAGE_HANDLE m = IoTHubMessage_CreateFromString("payload-1");
        check("message_string_roundtrip", m != NULL && strcmp(IoTHubMessage_GetString(m), "payload-1") == 0
            && IoTHubMessage_GetContentType(m) == IOTHUBMESSAGE_STRING);
        check("message_set_id", IoTHubMessage_SetMessageId(m, "mid-7") == IOTHUB_MESSAGE_OK
            && strcmp(IoTHubMessage_GetMessageId(m), "mid-7") == 0);
        check("message_set_correlation", IoTHubMessage_SetCorrelationId(m, "cid-9") == IOTHUB_MESSAGE_OK
            && strcmp(IoTHubMessage_GetCorrelationId(m), "cid-9") == 0);
        MAP_HANDLE props = IoTHubMessage_Properties(m);
        check("message_property_add", Map_Add(props, "k1", "v1") == MAP_OK && strcmp(Map_GetValueFromKey(props, "k1"), "v1") == 0);
        check("message_property_duplicate_rejected", Map_Add(props, "k1", "v2") == MAP_KEYEXISTS);
        IOTHUB_MESSAGE_HANDLE c = IoTHubMessage_Clone(m);
        check("message_clone", c != NULL && strcmp(IoTHubMessage_GetString(c), "payload-1") == 0
            && strcmp(Map_GetValueFromKey(IoTHubMessage_Properties(c), "k1"), "v1") == 0);
        IoTHubMessage_Destroy(c);
        IoTHubMessage_Destroy(m);

        static const unsigned char raw[] = { 1, 2, 3, 250 };
        m = IoTHubMessage_CreateFromByteArray(raw, sizeof(raw));
        const unsigned char* got = NULL;
        size_t len = 0;
        check("message_bytes_roundtrip", m != NULL && IoTHubMessage_GetByteArray(m, &got, &len) == IOTHUB_MESSAGE_OK
            && len == 4 && memcmp(got, raw, 4) == 0 && IoTHubMessage_GetContentType(m) == IOTHUBMESSAGE_BYTEARRAY);
        IoTHubMessage_Destroy(m);
    }

    printf("kat failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
