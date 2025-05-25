/******************************************************************************
Copyright (C) TLAY.IO

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

#include "x402-demo.h"
#include "boatinternal.h"
#include "base64.h"

#include "curl/curl.h"


// Memory allocated for receiving HTTP response
StringWithLen g_http_response;

#define HTTP_RECV_BUF_SIZE_STEP 1024

BOAT_RESULT HttpClientInit(void)
{
    BOAT_RESULT result;

    g_http_response.string_space = HTTP_RECV_BUF_SIZE_STEP;
    g_http_response.string_len = 0;

    g_http_response.string_ptr = BoatMalloc(HTTP_RECV_BUF_SIZE_STEP);

    if (g_http_response.string_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Fail to allocate Curl RESPONSE buffer.");
        result = BOAT_ERROR_COMMON_OUT_OF_MEMORY;
    }
    else
    {
        result = BOAT_SUCCESS;
    }

    return result;
}

void HttpClientDeinit(void)
{
    if (g_http_response.string_ptr != NULL)
    {
        BoatFree(g_http_response.string_ptr);
    }

    g_http_response.string_ptr = NULL;
    g_http_response.string_space = 0;
    g_http_response.string_len = 0;

    return;
}


__BOATSTATIC size_t HttpCurlWriteMemoryCallback(void *data_ptr, size_t size,
                                                size_t nmemb, void *userdata)
{
    size_t data_size;
    StringWithLen *mem;
    BUINT32 expand_size;
    BUINT32 expand_steps;
    BCHAR *expanded_str;
    BUINT32 expanded_to_space;

    mem = (StringWithLen *)userdata;

    // NOTE: For historic reasons, argument size is always 1 and nmemb is the
    // size of the data chunk to write. And size * nmemb doesn't include null
    // terminator even if the data were string.
    data_size = size * nmemb;

    // If response buffer has enough space:
    if (mem->string_space - mem->string_len > data_size) // 1 more byte reserved for null terminator
    {
        memcpy(mem->string_ptr + mem->string_len, data_ptr, data_size);
        mem->string_len += data_size;
        mem->string_ptr[mem->string_len] = '\0';
    }
    else // If response buffer has no enough space
    {
        // If malloc is supported, expand the response buffer in steps of
        // CURLPORT_RECV_BUF_SIZE_STEP.
        expand_size = data_size - (mem->string_space - mem->string_len) + 1; // plus 1 for null terminator
        expand_steps = (expand_size - 1) / HTTP_RECV_BUF_SIZE_STEP + 1;
        expanded_to_space = expand_steps * HTTP_RECV_BUF_SIZE_STEP + mem->string_space;

        expanded_str = BoatMalloc(expanded_to_space);

        if (expanded_str != NULL)
        {
            memcpy(expanded_str, mem->string_ptr, mem->string_len);
            memcpy(expanded_str + mem->string_len, data_ptr, data_size);
            BoatFree(mem->string_ptr);
            mem->string_ptr = expanded_str;
            mem->string_space = expanded_to_space;
            mem->string_len += data_size;
            mem->string_ptr[mem->string_len] = '\0';
        }
    }

    return data_size;
}



BOAT_RESULT HttpGetWithoutXPayment(const BCHAR *url_str,
                                   BOAT_OUT BCHAR **response_str_ptr,
                                   BOAT_OUT BUINT32 *response_len_ptr)
{
    CURL *curl_ctx_ptr = NULL;
    struct curl_slist *curl_opt_list_ptr = NULL;
    CURLcode curl_result;

    long info;
    BOAT_RESULT result = BOAT_ERROR;
    boat_try_declare;

    if (url_str == NULL || response_str_ptr == NULL || response_len_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Argument cannot be NULL.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    curl_ctx_ptr = curl_easy_init();

    if (curl_ctx_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "curl_easy_init() fails.");
        boat_throw(BOAT_ERROR_CURL_INIT_FAIL, cleanup);
    }

    // Set proxy if necessary
    // curl_result = curl_easy_setopt(curl_ctx_ptr, CURLOPT_PROXY, "http://127.0.0.1:1080");

    // Set RPC URL in format "<protocol>://<target name or IP>:<port>". e.g. "http://192.168.56.1:7545"
    curl_result = curl_easy_setopt(curl_ctx_ptr, CURLOPT_URL, url_str);
    if (curl_result != CURLE_OK)
    {
        BoatLog(BOAT_LOG_NORMAL, "Unknown URL: %s", url_str);
        boat_throw(BOAT_ERROR_CURL_SETOPT_FAIL, cleanup);
    }

    // Configure all protocols to be supported
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_PROTOCOLS, CURLPROTO_ALL);

    // Configure SSL Certification Verification
    // If certification file is not available, set them to 0.
    // See: https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_SSL_VERIFYHOST, 0);

    // To specify a certificate file or specify a path containing certification files
    // Only make sense when CURLOPT_SSL_VERIFYPEER is set to non-zero.
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_CAINFO, "/etc/certs/cabundle.pem");
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_CAPATH, "/etc/cert-dir");

    // Allow Re-direction
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_FOLLOWLOCATION, 1);

    // Verbose Debug Info.
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_VERBOSE, 1);

    // Set HTTP Type: GET
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_HTTPGET, 1L);

    // Set redirection: No
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_FOLLOWLOCATION, 0);

    // Set entire curl timeout in millisecond. This time includes DNS resloving.
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_TIMEOUT_MS, 30000L);

    // Set Connection timeout in millisecond
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_CONNECTTIMEOUT_MS, 10000L);

    // Set HTTP HEADER Options
    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "connection: keep-alive");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "Accept:/");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "Accept-Language:*");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    curl_easy_setopt(curl_ctx_ptr, CURLOPT_HTTPHEADER, curl_opt_list_ptr);

    // Set callback and receive buffer for RESPONSE
    // Clean up response buffer
    g_http_response.string_ptr[0] = '\0';
    g_http_response.string_len = 0;
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_WRITEDATA, &g_http_response);
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_WRITEFUNCTION, HttpCurlWriteMemoryCallback);


    // Perform the HTTP GET request
    curl_result = curl_easy_perform(curl_ctx_ptr);

    if (curl_result != CURLE_OK)
    {
        BoatLog(BOAT_LOG_NORMAL, "curl_easy_perform fails with CURLcode: %d.", curl_result);
        boat_throw(BOAT_ERROR_CURL_CODE_FAIL - curl_result, cleanup);
    }

    curl_result = curl_easy_getinfo(curl_ctx_ptr, CURLINFO_RESPONSE_CODE, &info);

    if ((curl_result == CURLE_OK) && (info == 200 || info == 201 || info == 402))
    {
        *response_str_ptr = g_http_response.string_ptr;
        *response_len_ptr = g_http_response.string_len;

        BoatLog(BOAT_LOG_VERBOSE, "Result Code: %ld", info);
        BoatLog(BOAT_LOG_VERBOSE, "Response: %s", *response_str_ptr);
    }
    else
    {
        BoatLog(BOAT_LOG_NORMAL, "curl_easy_getinfo fails with CURLcode: %d, HTTP response code %ld.", curl_result, info);
        boat_throw(BOAT_ERROR_CURL_INFO_FAIL - info, cleanup);
    }

    result = BOAT_SUCCESS;

    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    if (curl_opt_list_ptr != NULL)
    {
        curl_slist_free_all(curl_opt_list_ptr);
    }

    if (curl_ctx_ptr != NULL)
    {
        curl_easy_cleanup(curl_ctx_ptr);
    }

    return result;
}



BOAT_RESULT HttpGetWithXPayment(const BCHAR *url_str,
                                const BCHAR *payment_payload_str,
                                BOAT_OUT BCHAR **response_str_ptr,
                                BOAT_OUT BUINT32 *response_len_ptr)
{
    CURL *curl_ctx_ptr = NULL;
    struct curl_slist *curl_opt_list_ptr = NULL;
    CURLcode curl_result;

    long info;
    BOAT_RESULT result = BOAT_ERROR;
    BCHAR *payment_payload_base64 = NULL;
    boat_try_declare;

    if (url_str == NULL || payment_payload_str == NULL || response_str_ptr == NULL || response_len_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Argument cannot be NULL.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    BoatLog(BOAT_LOG_VERBOSE, "X-PAYMENT (JSON before Base64 encoding):\n%s", payment_payload_str);

    curl_ctx_ptr = curl_easy_init();

    if (curl_ctx_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "curl_easy_init() fails.");
        boat_throw(BOAT_ERROR_CURL_INIT_FAIL, cleanup);
    }

    // Set proxy if necessary
    // curl_result = curl_easy_setopt(curl_ctx_ptr, CURLOPT_PROXY, "http://127.0.0.1:1080");

    // Set RPC URL in format "<protocol>://<target name or IP>:<port>". e.g. "http://192.168.56.1:7545"
    curl_result = curl_easy_setopt(curl_ctx_ptr, CURLOPT_URL, url_str);
    if (curl_result != CURLE_OK)
    {
        BoatLog(BOAT_LOG_NORMAL, "Unknown URL: %s", url_str);
        boat_throw(BOAT_ERROR_CURL_SETOPT_FAIL, cleanup);
    }

    // Configure all protocols to be supported
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_PROTOCOLS, CURLPROTO_ALL);

    // Configure SSL Certification Verification
    // If certification file is not available, set them to 0.
    // See: https://curl.haxx.se/libcurl/c/CURLOPT_SSL_VERIFYPEER.html
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_SSL_VERIFYHOST, 0);

    // To specify a certificate file or specify a path containing certification files
    // Only make sense when CURLOPT_SSL_VERIFYPEER is set to non-zero.
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_CAINFO, "/etc/certs/cabundle.pem");
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_CAPATH, "/etc/cert-dir");

    // Allow Re-direction
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_FOLLOWLOCATION, 1);

    // Verbose Debug Info.
    // curl_easy_setopt(curl_ctx_ptr, CURLOPT_VERBOSE, 1);

    // Set HTTP Type: GET
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_HTTPGET, 1L);

    // Set redirection: No
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_FOLLOWLOCATION, 0);

    // Set entire curl timeout in millisecond. This time includes DNS resloving.
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_TIMEOUT_MS, 30000L);

    // Set Connection timeout in millisecond
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_CONNECTTIMEOUT_MS, 10000L);

    // Set HTTP HEADER Options
    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "connection: keep-alive");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    // Set X-Payment header
    payment_payload_base64 = BoatMalloc(sizeof("X-PAYMENT:")-1 + BASE64_ENCODE_OUT_SIZE(strlen(payment_payload_str)));
    if(payment_payload_base64 == NULL)
    {
        BoatLog(BOAT_LOG_VERBOSE, "Out of memory");
        boat_throw(BOAT_ERROR_COMMON_OUT_OF_MEMORY, cleanup);
    }

    strcpy(payment_payload_base64, "X-PAYMENT:");

    BoAT_base64_encode((BUINT8*)payment_payload_str, strlen(payment_payload_str), payment_payload_base64+sizeof("X-PAYMENT:")-1);

    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, payment_payload_base64);
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    // Set Access-Control-Expose-Headers
    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "Access-Control-Expose-Headers: X-PAYMENT-RESPONSE");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);
       

    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "Accept:/");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    curl_opt_list_ptr = curl_slist_append(curl_opt_list_ptr, "Accept-Language:*");
    if (curl_opt_list_ptr == NULL)
        boat_throw(BOAT_ERROR_CURL_SLIST_APPEND_FAIL, cleanup);

    curl_easy_setopt(curl_ctx_ptr, CURLOPT_HTTPHEADER, curl_opt_list_ptr);

    // Set callback and receive buffer for RESPONSE
    // Clean up response buffer
    g_http_response.string_ptr[0] = '\0';
    g_http_response.string_len = 0;
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_WRITEDATA, &g_http_response);
    curl_easy_setopt(curl_ctx_ptr, CURLOPT_WRITEFUNCTION, HttpCurlWriteMemoryCallback);


    // Perform the HTTP GET request
    curl_result = curl_easy_perform(curl_ctx_ptr);

    if (curl_result != CURLE_OK)
    {
        BoatLog(BOAT_LOG_NORMAL, "curl_easy_perform fails with CURLcode: %d.", curl_result);
        boat_throw(BOAT_ERROR_CURL_CODE_FAIL - curl_result, cleanup);
    }

    curl_result = curl_easy_getinfo(curl_ctx_ptr, CURLINFO_RESPONSE_CODE, &info);

    if ((curl_result == CURLE_OK) && (info == 200 || info == 201))
    {
        *response_str_ptr = g_http_response.string_ptr;
        *response_len_ptr = g_http_response.string_len;

        BoatLog(BOAT_LOG_VERBOSE, "Result Code: %ld", info);
        BoatLog(BOAT_LOG_VERBOSE, "Response: %s", *response_str_ptr);
    }
    else
    {
        if(curl_result == CURLE_OK)
        {
            BoatLog(BOAT_LOG_NORMAL, "curl_easy_getinfo fails with CURLcode: %d, HTTP response code %ld, Response: %s", curl_result, info, *response_str_ptr);
        }
        boat_throw(BOAT_ERROR_CURL_INFO_FAIL - info, cleanup);
    }

    result = BOAT_SUCCESS;

    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    // Clean Up

    if (curl_opt_list_ptr != NULL)
    {
        curl_slist_free_all(curl_opt_list_ptr);
    }

    if (curl_ctx_ptr != NULL)
    {
        curl_easy_cleanup(curl_ctx_ptr);
    }

    if(payment_payload_base64 != NULL)
    {
        BoatFree(payment_payload_base64);
    }

    return result;
}
