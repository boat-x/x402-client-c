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

#ifndef X402_DEMO_H
#define X402_DEMO_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#include "cJSON.h"

#include "boatiotsdk.h"
#include "boatEngine.h"
#include "boatosal.h"
#include "boatlog.h"
#include "boatkeystore.h"

typedef struct tPaymentRequestInfo_struct
{
    cJSON *cjson_http_response_ptr;
    BCHAR *network_str;
    BCHAR *amount_str;
    BCHAR *resource_str;
    BCHAR *payTo_str;
    BSINT32 timeout_s32;
    BCHAR *asset_str;
}tPaymentRequestInfo;

 // Private key of Payer (machine):
 extern const BCHAR *g_payer_key;
 

BOAT_RESULT makeEip3009TypedHash(BOAT_OUT BUINT8 typed_data_hash_out[32], const BCHAR *payer_address_str, const tPaymentRequestInfo * payment_request_info_ptr, BUINT64 validAfter_u64, BUINT64 validBefore_u64, BUINT8 nonce_u256[32]);
BOAT_RESULT HttpClientInit(void);
void HttpClientDeinit(void);
BOAT_RESULT HttpGetWithoutXPayment(const BCHAR *url_str, BOAT_OUT BCHAR **response_str_ptr, BOAT_OUT BUINT32 *response_len_ptr);
BOAT_RESULT HttpGetWithXPayment(const BCHAR *url_str, const BCHAR *payment_payload_str, BOAT_OUT BCHAR **response_str_ptr, BOAT_OUT BUINT32 *response_len_ptr);

#endif
