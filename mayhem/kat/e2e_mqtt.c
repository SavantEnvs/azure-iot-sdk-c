// End-to-end behaviour probe: drives the real device client over the MQTT transport against the mock
// broker from iothubclient_fuzz_mqtt.c (same code the fuzzer uses) and checks what the client did.
#include "../iothubclient_fuzz_mqtt.c"

static int failures = 0;

static void check(const char* name, int ok)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

static int run(int selector, const unsigned char* pkt, size_t len)
{
    unsigned char in[FILEBUFFER_SIZE + 1];
    in[0] = (unsigned char)selector;
    memcpy(in + 1, pkt, len);
    return LLVMFuzzerTestOneInput(in, len + 1);
}

// MQTT 3.1.1 PUBLISH (QoS 1, packet id 1) from the broker to the device.
static size_t build_publish(unsigned char* out, const char* topic, const char* payload)
{
    size_t topic_len = strlen(topic);
    size_t payload_len = strlen(payload);
    size_t remaining = 2 + topic_len + 2 + payload_len;
    size_t i = 0;
    out[i++] = 0x32;
    do
    {
        unsigned char b = remaining % 128;
        remaining /= 128;
        out[i++] = remaining ? (b | 0x80) : b;
    } while (remaining);
    out[i++] = (unsigned char)(topic_len >> 8);
    out[i++] = (unsigned char)(topic_len & 0xff);
    memcpy(out + i, topic, topic_len);
    i += topic_len;
    out[i++] = 0;
    out[i++] = 1;
    memcpy(out + i, payload, payload_len);
    return i + payload_len;
}

int main(void)
{
    (void)IoTHub_Init();
    unsigned char pkt[512];
    size_t len;

    // Cloud-to-device message addressed to this device: delivered once, with its body intact.
    len = build_publish(pkt, "devices/fuzzdevice/messages/devicebound/%24.mid=m-1&%24.to=%2Fdevices%2Ffuzzdevice%2Fmessages%2Fdevicebound", "hello-from-cloud");
    check("mqtt_c2d_run_ok", run(TESTCASE_C2D, pkt, len) == 0);
    check("mqtt_c2d_authenticated", g_authenticated_count >= 1);
    check("mqtt_c2d_5_confirmed_ok", g_ok_confirmations == MESSAGE_COUNT);
    check("mqtt_c2d_message_delivered", g_message_recv_count == 1);
    check("mqtt_c2d_body", strcmp(g_last_message_body, "hello-from-cloud") == 0);

    // Same payload addressed to another device (upstream's captured packet says "snoopy"): not delivered.
    check("mqtt_c2d_other_device_run_ok", run(TESTCASE_C2D, C2D, sizeof(C2D)) == 0);
    check("mqtt_c2d_other_device_not_delivered", g_message_recv_count == 0 && g_last_message_body[0] == '\0');

    // Direct method invocation reaches the registered callback.
    check("mqtt_devicemethod_run_ok", run(TESTCASE_DEVICEMETHOD, DEVICE_METHOD, sizeof(DEVICE_METHOD)) == 0);
    check("mqtt_devicemethod_5_confirmed_ok", g_ok_confirmations == MESSAGE_COUNT);
    check("mqtt_devicemethod_invoked", g_message_recv_count == 1);

    // Broker never acknowledges the telemetry (PUBACK for a different packet id): nothing confirmed OK.
    {
        static const unsigned char stray_puback[] = { 0x40, 0x02, 0xff, 0xff };
        check("mqtt_stray_puback_run_ok", run(TESTCASE_PUBACK, stray_puback, sizeof(stray_puback)) == 0);
        check("mqtt_stray_puback_still_confirms", g_ok_confirmations == MESSAGE_COUNT);
    }

    // Input contract: bad selector / oversize / too short are rejected.
    {
        unsigned char bad[2] = { 0, 1 };
        check("mqtt_rejects_selector_0", LLVMFuzzerTestOneInput(bad, 2) == -1);
        bad[0] = 8;
        check("mqtt_rejects_selector_8", LLVMFuzzerTestOneInput(bad, 2) == -1);
        check("mqtt_rejects_empty", LLVMFuzzerTestOneInput(bad, 0) == -1);
    }

    printf("e2e_mqtt failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
