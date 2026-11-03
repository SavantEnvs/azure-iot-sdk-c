// End-to-end behaviour probe: drives the real device client over the AMQP transport against the canned
// broker conversation from iothubclient_fuzz_amqp.c (same code the fuzzer uses) and checks what it did.
#include "../iothubclient_fuzz_amqp.c"

static int failures = 0;

static void check(const char* name, int ok)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

static int run(int id, const unsigned char* pkt, size_t len)
{
    unsigned char in[MAX_FUZZ_PACKET + 1];
    in[0] = (unsigned char)id;
    memcpy(in + 1, pkt, len);
    return LLVMFuzzerTestOneInput(in, len + 1);
}

int main(void)
{
    (void)IoTHub_Init();

    // Unmodified conversation: the hub accepts the connection and all 5 telemetry messages are confirmed.
    check("amqp_canned_run_ok", run(0, amqp_packets[0].data, amqp_packets[0].size) == 0);
    check("amqp_canned_authenticated", g_authenticated_count >= 1);
    check("amqp_canned_5_confirmed_ok", g_ok_confirmations == MESSAGE_COUNT);
    check("amqp_canned_send_iterations", send_iteration >= 20);

    // SASL tunnel header replaced by garbage: the connection never comes up, no message is confirmed OK.
    {
        static const unsigned char garbage[] = { 'N', 'O', 'T', 'A', 'M', 'Q', 'P', '!' };
        check("amqp_garbage_header_run_ok", run(0, garbage, sizeof(garbage)) == 0);
        check("amqp_garbage_header_not_authenticated", g_authenticated_count == 0);
    check("amqp_garbage_header_nothing_confirmed_ok", g_ok_confirmations == 0);
    }

    // Input contract.
    {
        unsigned char bad[2] = { 27, 1 };
        check("amqp_rejects_id_27", LLVMFuzzerTestOneInput(bad, 2) == -1);
        check("amqp_rejects_empty", LLVMFuzzerTestOneInput(bad, 0) == -1);
    }

    printf("e2e_amqp failures: %d\n", failures);
    return failures == 0 ? 0 : 1;
}
