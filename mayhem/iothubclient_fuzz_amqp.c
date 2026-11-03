// libFuzzer port of iothub_client/tests/iothubclient_fuzz_amqp/iothubclient_fuzz.c.
//
// Upstream's harness is an AFL file-input program that replays 27 canned "server" AMQP frames read from
// N.bin files in the cwd, substituting one of them with the fuzzed file. Here the canned frames are
// compiled in (amqp_packets.h) and the fuzzer input is: byte 0 = index of the server frame to replace
// (0..26), remaining bytes = the replacement frame. The device client, AMQP stack and mock TLS layer
// are otherwise unchanged from upstream.
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
#include "iothubtransportamqp.h"

#include "amqp_packets.h"

static const char* connectionString = "HostName=ericwol-hub.azure-devices.net;DeviceId=eeqq;SharedAccessSignature=SharedAccessSignature sr=ericwol-hub.azure-devices.net%2Fdevices%2Feeqq&sig=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX%3D&se=5605002146";

#define MESSAGE_COUNT        5
#define MAX_FUZZ_PACKET      4096
#define LOOP_LIMIT           2000

static bool g_continueRunning;
static size_t g_message_count_send_confirmations;
static size_t g_ok_confirmations;
static size_t g_authenticated_count;
static size_t g_message_recv_count;

static unsigned char fuzzpacket_buffer[MAX_FUZZ_PACKET];
static size_t fuzzpacket_len;
static int fuzzpacket_id;
static int send_iteration;

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
    (void)message;
    (void)user_context;
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

// Fills file_buffer with server frame i (or the fuzzed frame if it replaces i); returns its length.
static size_t load_packet(int i, unsigned char file_buffer[], size_t size)
{
    size_t len;
    const unsigned char* src;
    if (fuzzpacket_id == i)
    {
        src = fuzzpacket_buffer;
        len = fuzzpacket_len;
    }
    else
    {
        src = amqp_packets[i].data;
        len = amqp_packets[i].size;
    }
    if (len > size)
    {
        len = size;
    }
    memcpy(file_buffer, src, len);
    return len;
}

static int tlsio_fuzz_send(CONCRETE_IO_HANDLE tls_io, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    (void)tls_io;

    size_t size_read;
    unsigned char file_buffer[4096];

    switch (send_iteration)
    {
        case 0: // client SASL tunnel request
            size_read = load_packet(0, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            size_read = load_packet(1, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 1: // client SASL Init
            size_read = load_packet(2, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 2: // client connection header
            size_read = load_packet(3, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 3: // send Connection Open
            size_read = load_packet(4, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 4: // send CONNECTION begin
            size_read = load_packet(5, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 5: // send SESSION attach $cbs-sender
            size_read = load_packet(6, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 6: // send SESSION attach $cbs-receiver
            size_read = load_packet(8, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            size_read = load_packet(7, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 7: // send_flow
            size_read = load_packet(9, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 8: // session_send_transfer: send SAS token to hub
            size_read = load_packet(10, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 9: // send_disposition
            break;

        case 10: // send_attach (events)
            size_read = load_packet(11, file_buffer, sizeof(file_buffer));
            if (size_read > 0x5f + 41 && size > 31 + 41)
            {
                memcpy(&file_buffer[0x1f], &((const char*)buffer)[31], 41);
                memcpy(&file_buffer[0x5f], &((const char*)buffer)[31], 41);
            }
            received_queue_add(file_buffer, size_read);
            size_read = load_packet(12, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 11: // send_attach (twin)
            size_read = load_packet(14, file_buffer, sizeof(file_buffer));
            if (size_read > 0x60 + 41 && size > 31 + 41)
            {
                memcpy(&file_buffer[0x1f], &((const char*)buffer)[31], 41);
                memcpy(&file_buffer[0x60], &((const char*)buffer)[31], 41);
            }
            received_queue_add(file_buffer, size_read);
            size_read = load_packet(15, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 12: // send_attach (devicebound)
            size_read = load_packet(13, file_buffer, sizeof(file_buffer));
            if (size_read > 0xb8 + 41 && size > 31 + 41)
            {
                memcpy(&file_buffer[0x1f], &((const char*)buffer)[31], 41);
                memcpy(&file_buffer[0xb8], &((const char*)buffer)[31], 41);
            }
            received_queue_add(file_buffer, size_read);
            break;

        case 13:
            size_read = load_packet(16, file_buffer, sizeof(file_buffer));
            if (size_read > 0x60 + 41 && size > 31 + 41)
            {
                memcpy(&file_buffer[0x1f], &((const char*)buffer)[31], 41);
                memcpy(&file_buffer[0x60], &((const char*)buffer)[31], 41);
            }
            received_queue_add(file_buffer, size_read);
            break;

        case 14: // session_send_transfer (twin get)
            size_read = load_packet(22, file_buffer, sizeof(file_buffer));
            if (size_read > 0x4d + 36 && size > 0x3e + 36)
            {
                memcpy(&file_buffer[0x4d], &((const char*)buffer)[0x3e], 36);
            }
            received_queue_add(file_buffer, size_read);
            break;

        case 15: // send_flow
        case 16: // send_flow
            break;

        case 17: // session_send_transfer (twin get)
            size_read = load_packet(23, file_buffer, sizeof(file_buffer));
            if (size_read > 0x4d + 36 && size > 0x3e + 36)
            {
                memcpy(&file_buffer[0x4d], &((const char*)buffer)[0x3e], 36);
            }
            received_queue_add(file_buffer, size_read);
            break;

        case 18: // session_send_disposition
            size_read = load_packet(17, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 19: // send_attach (methods_responses_link)
            size_read = load_packet(19, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 20: // send_attach (methods_requests_link)
            size_read = load_packet(21, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 21: // session_send_transfer (telemetry)
            size_read = load_packet(26, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 22: // session_send_disposition
            size_read = load_packet(18, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;

        case 23: // session_send_transfer (twin PUT)
            size_read = load_packet(25, file_buffer, sizeof(file_buffer));
            if (size_read > 0x4c + 36 && size > 0x70 + 36)
            {
                memcpy(&file_buffer[0x4c], &((const char*)buffer)[0x70], 36);
            }
            received_queue_add(file_buffer, size_read);
            break;

        case 24: // remaining packets
            size_read = load_packet(20, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            size_read = load_packet(24, file_buffer, sizeof(file_buffer));
            received_queue_add(file_buffer, size_read);
            break;
    }

    send_iteration++;
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
    if (size < 2 || size - 1 > MAX_FUZZ_PACKET || data[0] >= 27)
    {
        return -1;
    }

    fuzzpacket_id = data[0];
    fuzzpacket_len = size - 1;
    memcpy(fuzzpacket_buffer, data + 1, fuzzpacket_len);

    send_iteration = 0;
    g_continueRunning = true;
    g_message_count_send_confirmations = 0;
    g_ok_confirmations = 0;
    g_authenticated_count = 0;
    g_message_recv_count = 0;

    size_t messages_sent = 0;
    IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle = IoTHubDeviceClient_LL_CreateFromConnectionString(connectionString, AMQP_Protocol);
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
