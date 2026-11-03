// libFuzzer port of iothub_client/tests/iothubclient_fuzz_mqtt/iothubclient_fuzz.c.
//
// Upstream's harness is an AFL file-input program (`iothubclient_fuzz_mqtt <TESTCASE> <file>`). Here the
// fuzzer input is: byte 0 = test case selector (1..7: CONACK, PUBACK, SUBACK, TWINGET, C2D,
// DEVICEMETHOD, TWINUPDATE), remaining bytes = the server->client MQTT packet that replaces the canned reply
// (what upstream reads from <file>). The device client, MQTT stack and mock TLS layer are unchanged.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iothub.h"
#include "iothub_device_client_ll.h"
#include "iothub_client_options.h"
#include "iothub_message.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/xio.h"
#include "iothubtransportmqtt.h"

static const char* connectionString = "HostName=fuzz-hub.azure-devices.net;DeviceId=fuzzdevice;SharedAccessKey=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=";
#define MESSAGE_COUNT        5
#define LOOP_LIMIT           100
#define FILEBUFFER_SIZE      2048

static bool g_continueRunning;
static size_t g_message_count_send_confirmations;
static size_t g_ok_confirmations;
static size_t g_authenticated_count;
static char g_last_message_body[64];
static size_t g_message_recv_count;
static size_t conack_count;
static int dowork_iteration;

// MQTT PACKETS
static unsigned char PINGRESP[] = { 0xd0, 0x00 };
static unsigned char CONACK[] = { 0x20, 0x02, 0x00, 0x00 };
static unsigned char PUBACK[] = { 0x40, 0x02, 0x00, 0x05 };
static unsigned char SUBACK[] = { 0x90, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static unsigned char C2D[] = { 0x32, 0x95, 0x01, 0x00, 0x84, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x79, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x2f, 0x25, 0x32, 0x34, 0x2e, 0x6d, 0x69, 0x64, 0x3d, 0x39, 0x39, 0x32, 0x33, 0x64, 0x35, 0x65, 0x31, 0x2d, 0x32, 0x37, 0x35, 0x39, 0x2d, 0x34, 0x37,
                               0x30, 0x36, 0x2d, 0x39, 0x35, 0x37, 0x61, 0x2d, 0x38, 0x63, 0x38, 0x37, 0x32, 0x38, 0x64, 0x36, 0x63, 0x37, 0x65, 0x61, 0x26, 0x25, 0x32, 0x34, 0x2e, 0x74, 0x6f, 0x3d, 0x25, 0x32, 0x46, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x73, 0x25, 0x32, 0x46, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x79, 0x25, 0x32, 0x46, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x25, 0x32, 0x46, 0x64, 0x65, 0x76, 0x69,
                               0x63, 0x65, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x00, 0x04, 0x7b, 0x22, 0x66, 0x6f, 0x6f, 0x22, 0x3a, 0x22, 0x62, 0x61, 0x72, 0x22, 0x7d };
static unsigned char DEVICE_METHOD[] = { 0x30, 0x31, 0x00, 0x22, 0x24, 0x69, 0x6f, 0x74, 0x68, 0x75, 0x62, 0x2f, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x2f, 0x50, 0x4f, 0x53, 0x54, 0x2f, 0x62, 0x6c, 0x69, 0x6e, 0x6b, 0x2f, 0x3f, 0x24, 0x72, 0x69, 0x64, 0x3d, 0x31, 0x7b, 0x22, 0x66, 0x6f, 0x6f, 0x22, 0x3a, 0x22, 0x62, 0x61, 0x72, 0x22, 0x7d };
static unsigned char TWIN_UPDATE[] = { 0x30, 0x4a, 0x00, 0x31, 0x24, 0x69, 0x6f, 0x74, 0x68, 0x75, 0x62, 0x2f, 0x74, 0x77, 0x69, 0x6e, 0x2f, 0x50, 0x41, 0x54, 0x43, 0x48, 0x2f, 0x70, 0x72, 0x6f, 0x70, 0x65, 0x72, 0x74, 0x69, 0x65, 0x73, 0x2f, 0x64, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x2f, 0x3f, 0x24, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x34, 0x7b, 0x22, 0x64, 0x64, 0x64, 0x64, 0x22, 0x3a, 0x34, 0x2c, 0x22, 0x24, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x34, 0x7d };
static unsigned char TWIN_GET[] = { 0x32, 0x5b, 0x00, 0x1c, 0x24, 0x69, 0x6f, 0x74, 0x68, 0x75, 0x62, 0x2f, 0x74, 0x77, 0x69, 0x6e, 0x2f, 0x72, 0x65, 0x73, 0x2f, 0x32, 0x30, 0x30, 0x2f, 0x3f, 0x24, 0x72, 0x69, 0x64, 0x3d, 0x39, 0x7b, 0x22, 0x64, 0x65, 0x73, 0x69, 0x72, 0x65, 0x64, 0x22, 0x3a, 0x7b, 0x22, 0x64, 0x64, 0x64, 0x64, 0x22, 0x3a, 0x34, 0x2c, 0x22, 0x24, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x34, 0x7d, 0x2c, 0x22, 0x72, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x22, 0x3a, 0x7b, 0x22, 0x24, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x31, 0x7d, 0x7d };
static const char topic_twin_get[] = "$iothub/twin/GET";

enum TestCase {
    TESTCASE_NONE,
    TESTCASE_CONACK,
    TESTCASE_PUBACK,
    TESTCASE_SUBACK,
    TESTCASE_TWINGET,
    TESTCASE_C2D,
    TESTCASE_DEVICEMETHOD,
    TESTCASE_TWINUPDATE
};
static enum TestCase test_case = TESTCASE_NONE;
static unsigned char filebuffer[FILEBUFFER_SIZE];
static size_t filebuffer_len;

static void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    (void)userContextCallback;
    g_message_count_send_confirmations++;
    if (result == IOTHUB_CLIENT_CONFIRMATION_OK)
    {
        g_ok_confirmations++;
    }
}

static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* user_context)
{
    (void)reason;
    (void)user_context;
    if (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED)
    {
        g_authenticated_count++;
    }
}

static IOTHUBMESSAGE_DISPOSITION_RESULT receive_msg_callback(IOTHUB_MESSAGE_HANDLE message, void* user_context)
{
    (void)user_context;
    const unsigned char* body = NULL;
    size_t body_len = 0;
    if (IoTHubMessage_GetByteArray(message, &body, &body_len) == IOTHUB_MESSAGE_OK && body != NULL)
    {
        size_t n = body_len < sizeof(g_last_message_body) - 1 ? body_len : sizeof(g_last_message_body) - 1;
        memcpy(g_last_message_body, body, n);
        g_last_message_body[n] = '\0';
    }
    g_message_recv_count++;
    return IOTHUBMESSAGE_ACCEPTED;
}

static int device_method_callback(const char* method_name, const unsigned char* payload, size_t size, unsigned char** response, size_t* response_size, void* userContextCallback)
{
    (void)method_name;
    (void)payload;
    (void)size;
    (void)userContextCallback;

    g_message_recv_count++;
    char method_status[] = "{\"status\":200}";
    *response_size = strlen(method_status);
    *response = malloc(*response_size);
    (void)memcpy(*response, method_status, *response_size);
    return 200;
}

static void deviceTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payLoad, size_t size, void* userContextCallback)
{
    (void)update_state;
    (void)payLoad;
    (void)size;
    (void)userContextCallback;
}

////////////////////////////////////////////////////////////////////////////////////////
typedef struct queue_item
{
    const unsigned char* data;
    size_t size;
    struct queue_item* next;
} QUEUE_ITEM;

static ON_BYTES_RECEIVED on_bytes_received_callback;
static void* on_bytes_received_context_callback;

static QUEUE_ITEM* received_queue = NULL;

static void received_queue_add(const unsigned char* buffer, size_t size)
{
    QUEUE_ITEM* item = malloc(sizeof(QUEUE_ITEM));
    if (item == NULL) return;
    item->data = malloc(size > 0 ? size : 1);
    if (item->data == NULL)
    {
        free(item);
        return;
    }
    memcpy((void*)item->data, buffer, size);
    item->size = size;
    item->next = NULL;

    if (received_queue == NULL)
    {
        received_queue = item;
    }
    else
    {
        QUEUE_ITEM* node = received_queue;
        while (node->next != NULL)
        {
            node = node->next;
        }
        node->next = item;
    }
}

static QUEUE_ITEM* received_queue_remove(void)
{
    QUEUE_ITEM* current = received_queue;
    if (received_queue != NULL)
    {
        received_queue = received_queue->next;
    }
    return current;
}

static void received_queue_free(QUEUE_ITEM* removed)
{
    free((void*)removed->data);
    free(removed);
}

static void received_queue_clear(void)
{
    while (received_queue != NULL)
    {
        received_queue_free(received_queue_remove());
    }
}

// Mock broker: parses what the *client* sent (always well formed) and queues the canned reply.
static size_t mqtt_parse_packet_length(const unsigned char* buffer, size_t* idx)
{
    unsigned char encodedByte;
    size_t multiplier = 1;
    size_t value = 0;
    do
    {
        encodedByte = buffer[*idx];
        *idx += 1;
        value += (encodedByte & 127) * multiplier;
        multiplier *= 128;
    } while ((encodedByte & 128) != 0);
    return value;
}

static void mqtt_parse_packet(const unsigned char* buffer, size_t size)
{
    (void)size;
    int qos;
    int subscribe_topic_num;
    size_t topic_len;
    char topic_name[512];

    size_t idx = 0;
    unsigned char mqtt_control_packet_type = buffer[idx] >> 4;

    idx++;
    size_t packet_len = mqtt_parse_packet_length(buffer, &idx);

    switch (mqtt_control_packet_type)
    {
        case 1: //CONNECT
            if (test_case == TESTCASE_CONACK && conack_count == 0)
            {
                received_queue_add(filebuffer, filebuffer_len);
                conack_count++;
            }
            else
            {
                received_queue_add(CONACK, sizeof(CONACK));
            }
            break;

        case 3: //PUBLISH
            topic_len = ((size_t)buffer[idx] << 8) + ((size_t)buffer[idx + 1]);
            idx += 2;
            qos = (buffer[0] >> 1) & 0x03;
            if (qos > 0)
            {
                PUBACK[2] = buffer[idx + topic_len];      // packet id
                PUBACK[3] = buffer[idx + topic_len + 1];

                if (test_case == TESTCASE_PUBACK &&
                    PUBACK[2] == filebuffer[2] && PUBACK[3] == filebuffer[3])
                {
                    received_queue_add(filebuffer, filebuffer_len);
                }
                else
                {
                    received_queue_add(PUBACK, sizeof(PUBACK));
                }
            }

            if (topic_len >= sizeof(topic_name))
            {
                topic_len = sizeof(topic_name) - 1;
            }
            memset(topic_name, 0, sizeof(topic_name));
            memcpy(topic_name, &buffer[idx], topic_len);

            if (memcmp(topic_twin_get, topic_name, sizeof(topic_twin_get) - 1) == 0)
            {
                if (test_case == TESTCASE_TWINGET)
                {
                    received_queue_add(filebuffer, filebuffer_len);
                }
                else
                {
                    TWIN_GET[31] = topic_name[strlen(topic_name) - 1];
                    received_queue_add(TWIN_GET, sizeof(TWIN_GET));
                }
            }
            break;

        case 8: //SUBSCRIBE
            subscribe_topic_num = 0;
            SUBACK[1] = 0x02;
            SUBACK[2] = buffer[idx];      // packet id
            SUBACK[3] = buffer[idx + 1];
            packet_len -= 2;
            idx += 2;
            while (packet_len)
            {
                topic_len = ((size_t)buffer[idx] << 8) + ((size_t)buffer[idx + 1]);
                idx += topic_len + 2;
                packet_len -= topic_len + 2;

                // subscribe qos
                idx++;
                packet_len--;

                SUBACK[1] += 1;
                SUBACK[4 + subscribe_topic_num] = 0x01;
                subscribe_topic_num++;
            }

            if (test_case == TESTCASE_SUBACK &&
                SUBACK[2] == filebuffer[2] && SUBACK[3] == filebuffer[3])
            {
                received_queue_add(filebuffer, filebuffer_len);
            }
            else
            {
                received_queue_add(SUBACK, 4 + (size_t)subscribe_topic_num);
            }
            break;

        case 12: //PINGREQ
            received_queue_add(PINGRESP, sizeof(PINGRESP));
            break;
    }
}

static void* tlsio_fuzz_CloneOption(const char* name, const void* value)
{
    (void)name;
    void* result;
    if (mallocAndStrcpy_s((char**)&result, (const char*)value) != 0)
    {
        result = NULL;
    }
    return result;
}

static void tlsio_fuzz_DestroyOption(const char* name, const void* value)
{
    (void)name;
    (void)value;
}

static int tlsio_fuzz_setoption(CONCRETE_IO_HANDLE tls_io, const char* optionName, const void* value)
{
    (void)tls_io;
    (void)optionName;
    (void)value;
    return 0;
}

static OPTIONHANDLER_HANDLE tlsio_fuzz_retrieveoptions(CONCRETE_IO_HANDLE handle)
{
    (void)handle;
    return OptionHandler_Create(tlsio_fuzz_CloneOption, tlsio_fuzz_DestroyOption, tlsio_fuzz_setoption);
}

static CONCRETE_IO_HANDLE tlsio_fuzz_create(void* io_create_parameters)
{
    (void)io_create_parameters;
    return (CONCRETE_IO_HANDLE*)malloc(sizeof(CONCRETE_IO_HANDLE));
}

static void tlsio_fuzz_destroy(CONCRETE_IO_HANDLE tls_io)
{
    if (tls_io)
    {
        free(tls_io);
    }
}

static int tlsio_fuzz_open(CONCRETE_IO_HANDLE tls_io, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received,
    void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    (void)tls_io;
    on_bytes_received_callback = on_bytes_received;
    on_bytes_received_context_callback = on_bytes_received_context;
    (void)on_io_error;
    (void)on_io_error_context;

    on_io_open_complete(on_io_open_complete_context, IO_OPEN_OK);
    return 0;
}

static int tlsio_fuzz_close(CONCRETE_IO_HANDLE tls_io, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    (void)tls_io;
    received_queue_clear();
    // A real TLS adapter reports completion of the close; callers wait for it (mqtt for up to 2.5 s).
    if (on_io_close_complete != NULL)
    {
        on_io_close_complete(callback_context);
    }
    return 0;
}

static int tlsio_fuzz_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    (void)tls_io;

    mqtt_parse_packet(buffer, size);

    on_send_complete(callback_context, IO_SEND_OK);
    return 0;
}

static void tlsio_fuzz_dowork(CONCRETE_IO_HANDLE tls_io)
{
    (void)tls_io;

    if (received_queue != NULL)
    {
        QUEUE_ITEM* item = received_queue_remove();
        on_bytes_received_callback(on_bytes_received_context_callback, item->data, item->size);
        received_queue_free(item);
    }

    dowork_iteration++;
    if (dowork_iteration == 20)
    {
        if (test_case == TESTCASE_DEVICEMETHOD || test_case == TESTCASE_C2D || test_case == TESTCASE_TWINUPDATE)
        {
            received_queue_add(filebuffer, filebuffer_len);
        }
    }
}

static const IO_INTERFACE_DESCRIPTION tlsio_fuzz_interface_description =
{
    tlsio_fuzz_retrieveoptions,
    tlsio_fuzz_create,
    tlsio_fuzz_destroy,
    tlsio_fuzz_open,
    tlsio_fuzz_close,
    tlsio_fuzz_send,
    tlsio_fuzz_dowork,
    tlsio_fuzz_setoption
};

// The SDK is built with use_openssl=OFF, so the TLS adapter it asks for is this mock.
const IO_INTERFACE_DESCRIPTION* tlsio_openssl_get_interface_description(void)
{
    return &tlsio_fuzz_interface_description;
}

static ssize_t discard_write(void* cookie, const char* buf, size_t n)
{
    (void)cookie;
    (void)buf;
    return (ssize_t)n;
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    // SDK trace logging goes to stdout; discard it in-process (no file path involved).
    cookie_io_functions_t discard = { NULL, discard_write, NULL, NULL };
    FILE* sink = fopencookie(NULL, "w", discard);
    if (sink != NULL)
    {
        stdout = sink;
    }
    (void)IoTHub_Init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2 || data[0] < TESTCASE_CONACK || data[0] > TESTCASE_TWINUPDATE || size - 1 >= FILEBUFFER_SIZE)
    {
        return -1;
    }

    test_case = (enum TestCase)data[0];
    memset(filebuffer, 0, sizeof(filebuffer));
    filebuffer_len = size - 1;
    memcpy(filebuffer, data + 1, filebuffer_len);

    g_continueRunning = true;
    g_message_count_send_confirmations = 0;
    g_ok_confirmations = 0;
    g_authenticated_count = 0;
    g_last_message_body[0] = '\0';
    g_message_recv_count = 0;
    conack_count = 0;
    dowork_iteration = 0;

    size_t messages_sent = 0;
    IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle = IoTHubDeviceClient_LL_CreateFromConnectionString(connectionString, MQTT_Protocol);
    if (device_ll_handle != NULL)
    {
        bool traceOn = true;
        IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_LOG_TRACE, &traceOn);

        (void)IoTHubDeviceClient_LL_SetConnectionStatusCallback(device_ll_handle, connection_status_callback, NULL);
        (void)IoTHubDeviceClient_LL_SetMessageCallback(device_ll_handle, receive_msg_callback, NULL);
        (void)IoTHubDeviceClient_LL_GetTwinAsync(device_ll_handle, deviceTwinCallback, NULL);
        (void)IoTHubDeviceClient_LL_SetDeviceMethodCallback(device_ll_handle, device_method_callback, NULL);
        (void)IoTHubDeviceClient_LL_SetDeviceTwinCallback(device_ll_handle, deviceTwinCallback, NULL);

        for (int loop_count = 0; g_continueRunning && loop_count < LOOP_LIMIT; loop_count++)
        {
            if (messages_sent < MESSAGE_COUNT)
            {
                IOTHUB_MESSAGE_HANDLE message_handle = IoTHubMessage_CreateFromString("test_message");
                IoTHubDeviceClient_LL_SendEventAsync(device_ll_handle, message_handle, send_confirm_callback, NULL);
                IoTHubMessage_Destroy(message_handle);
                messages_sent++;
            }
            else if (g_message_count_send_confirmations >= MESSAGE_COUNT && g_message_recv_count > 0)
            {
                g_continueRunning = false;
            }

            IoTHubDeviceClient_LL_DoWork(device_ll_handle);
        }

        IoTHubDeviceClient_LL_Destroy(device_ll_handle);
    }
    received_queue_clear();
    return 0;
}
