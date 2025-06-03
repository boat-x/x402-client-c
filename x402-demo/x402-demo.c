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

/******************************************************************************
 Before first-time compilation, copy credentials.key.example to credentials.key
 and replace g_payer_key value with actual payer's private key
******************************************************************************/
//! Private Key
#include "credentials.key"

//! Resource URL for the x402 demo
const BCHAR *g_x402_server_url = "http://127.0.0.1:4021/weather";

//! Chain ID
const BUINT32 g_chain_id = 8453;  //  Not useful for x402 scenario, but keep for standard BoAT initialization procedure

//! Wallet Object
BoatEthWallet *g_ethereum_wallet_ptr = NULL;

//! Keypair Index
BUINT8 g_keypairIndex = 0;

//! Network Index
BUINT8 g_networkIndex = 0;  //  Not useful for x402 scenario, but keep for standard BoAT initialization procedure

/*!*****************************************************************************
@brief Create an ECDSA keypair for the demo

@details
  This function creates an ECDSA secp256k1 keypair for the payer in the x402 demo.
  The keypair is later used to create the Ethereum wallet object.
  
  Note: In the x402 demo, BoAT SDK is used only to sign the Payment Payload and
  doesn't actually send transaction to the network. 

@param[in] {BCHAR*} nativePrivateKey
    The 256-bit native private key in HEX string with leading "0x".

@param[in] {BCHAR*} keypairName
    The name of the keypair. The exact name is not care.

@return
  This function returns BOAT_SUCCESS if the keypair is successfully created.\n
  Otherwise it returns an error code.

*******************************************************************************/
BOAT_RESULT ethereum_createKeypair(const BCHAR *nativePrivateKey, BCHAR * keypairName)
{
    BOAT_RESULT result = BOAT_SUCCESS;
    BoatKeypairPriKeyCtx_config keypair_config = {0};
    BUINT8 binFormatKey[32]           = {0};

    (void)binFormatKey; //avoid warning

	/* keypair_config value assignment */
    keypair_config.prikey_genMode = BOAT_KEYPAIR_PRIKEY_GENMODE_EXTERNAL_INJECTION;
    keypair_config.prikey_format  = BOAT_KEYPAIR_PRIKEY_FORMAT_NATIVE;
    keypair_config.prikey_type    = BOAT_KEYPAIR_PRIKEY_TYPE_SECP256K1;
    UtilityHexToBin(binFormatKey, 32, nativePrivateKey, TRIMBIN_TRIM_NO, BOAT_FALSE);
    keypair_config.prikey_content.field_ptr = binFormatKey;
    keypair_config.prikey_content.field_len = 32;


	/* create ethereum keypair */
    result = BoatKeypairCreate( &keypair_config, keypairName,BOAT_STORE_TYPE_RAM);

    if (result < 0)
	{
        BoatLog(BOAT_LOG_CRITICAL, "create one-time keypair failed.");
        return BOAT_ERROR_WALLET_CREATE_FAIL;
    }
    g_keypairIndex = result;
    
    return BOAT_SUCCESS;
}


/*!*****************************************************************************
@brief Create an Ethereum-compatible network for the demo

@details
  This function creates an Ethereum-compatible network for the x402 demo.
  The network is later used to create the Ethereum wallet object.
  
  This function doesn't take any parameter.
  
  Note: In the x402 demo, BoAT SDK is used only to sign the Payment Payload and
  doesn't actually send transaction to the network. This configuration is
  required to meet the BoAT SDK usage, but its value is not care in the demo. 

@return
  This function returns BOAT_SUCCESS if the network is successfully created.\n
  Otherwise it returns an error code.

*******************************************************************************/
BOAT_RESULT createEthereumNetwork()
{
    BOAT_RESULT result = BOAT_SUCCESS;
    BoatEthNetworkConfig network_config = {0};

    network_config.chain_id             = g_chain_id;
    network_config.eip155_compatibility = BOAT_TRUE;
    network_config.node_url_str[0] = '\0';  // x402 doesn't visit RPC node from device side.

    result = BoATEthNetworkCreate( &network_config, BOAT_STORE_TYPE_RAM);

    if (result < 0)
	{
        //BoatLog(BOAT_LOG_CRITICAL, "create one-time wallet failed.");
        return BOAT_ERROR_WALLET_CREATE_FAIL;
    }
    g_networkIndex = result;
    
    return BOAT_SUCCESS;
}



/*!*****************************************************************************
@brief Get a string from a cJSON object item

@details
  This is a utility function to get a string value with a given key name from
  a cJSON object item.
  

@param[out] {BCHAR**} item_str_ptr
    An address of BCHAR* type to receive the address of the parsed string with\n
    the key name given by [item_name_str].\n
    The caller should not free the memory pointed by the received address.

@param[in] {cJSON*} cjson_object_ptr
    Pointer to an cJSON object containing the number to get.

@param[in] {BCHAR*} item_name_str
    A string of the key name (of the JSON key-value pare) to get nummeric value from.

@return
  This function returns BOAT_SUCCESS if the string value is successfully got.\n
  It returns NULL if [item_name_str] is not found or is not a string value.

*******************************************************************************/
BOAT_RESULT getStringFromcJson(BOAT_OUT BCHAR **item_str_ptr, const cJSON * cjson_object_ptr, const BCHAR * item_name_str)
{
    cJSON *cjson_item_ptr = NULL;

    if(item_str_ptr == NULL || cjson_object_ptr == NULL || item_name_str == NULL)
    {
        return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }

    // Obtain string item from object
    cjson_item_ptr = cJSON_GetObjectItem(cjson_object_ptr, item_name_str);
    if (cjson_item_ptr == NULL)
    {
        *item_str_ptr = NULL;

        BoatLog(BOAT_LOG_NORMAL, "\"%s\" is not a child item of object \"%s\".", item_name_str, cjson_object_ptr->child->string);
        return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }

    // Get NULL-terminated string from item
    *item_str_ptr = cJSON_GetStringValue(cjson_item_ptr);
    if (*item_str_ptr == NULL)
    {
		BoatLog(BOAT_LOG_NORMAL, "Item \"%s\" is not a string.", item_name_str);
		return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }
    else
    {
        BoatLog(BOAT_LOG_VERBOSE, "\"%s\": \"%s\"", item_name_str, *item_str_ptr);
    }

    return BOAT_SUCCESS;
}


/*!*****************************************************************************
@brief Get a number from a cJSON object item

@details
  This is a utility function to get a nummeric value with a given key name from
  a cJSON object item.
  
  In JSON, all numeric values are regarded as float number. cJSON parses the
  value as double and rounds it to the nearest integer. Thus, this function
  returns both a 32-bit signed integer and a double value. [item_int_ptr] and
  [item_double_ptr] cannot be both NULL.

@param[out] {BSINT32*} item_int_ptr
    An address of BSINT32 type to receive the parsed number with the key name\n
    given by [item_name_str].\n
    It can be NULL if a integer value is not required. In this case,\n
    [item_double_ptr] cannot be NULL.

@param[out] {double*} item_double_ptr
    An address of double type to receive the parsed number with the key name\n
    given by [item_name_str].\n
    It can be NULL if a double value is not required. In this case,\n
    [item_int_ptr] cannot be NULL.

@param[in] {cJSON*} cjson_object_ptr
    Pointer to an cJSON object containing the number to get.

@param[in] {BCHAR*} item_name_str
    A string of the key name (of the JSON key-value pare) to get nummeric value from.

@return
  This function returns BOAT_SUCCESS if the numeric value is successfully got.\n
  It returns NULL if [item_name_str] is not found or is not a numeric value.

*******************************************************************************/
BOAT_RESULT getNumberFromcJson(BOAT_OUT BSINT32 *item_int_ptr, BOAT_OUT double *item_double_ptr, const cJSON * cjson_object_ptr, const BCHAR * item_name_str)
{
    cJSON *cjson_item_ptr = NULL;

    if((item_int_ptr == NULL && item_double_ptr == NULL) || cjson_object_ptr == NULL || item_name_str == NULL)
    {
        return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }

    // Obtain string item from object
    cjson_item_ptr = cJSON_GetObjectItem(cjson_object_ptr, item_name_str);
    if (cjson_item_ptr == NULL)
    {
        BoatLog(BOAT_LOG_NORMAL, "\"%s\" is not a child item of object \"%s\".", item_name_str, cjson_object_ptr->child->string);
        return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }

    if(!cJSON_IsNumber(cjson_item_ptr))
    {
        BoatLog(BOAT_LOG_NORMAL, "\"%s\" is not a numeric value.", item_name_str);
        return BOAT_ERROR_COMMON_INVALID_ARGUMENT;
    }

    // Get integer and/or double value from item
    if(item_int_ptr != NULL)    *item_int_ptr = cjson_item_ptr->valueint;
    if(item_double_ptr != NULL) *item_double_ptr = cjson_item_ptr->valuedouble;

    BoatLog(BOAT_LOG_VERBOSE, "\"%s\": \"%d\" (integer) or \"%lf\" (double)", item_name_str, cjson_item_ptr->valueint, cjson_item_ptr->valuedouble);

    return BOAT_SUCCESS;
}


/*!*****************************************************************************
@brief Parse x402 Payment Request

@details
  This function parses the Payment Request returned by a x402 server.

  Payment Request is a JSON string like:
  
    {
        "x402Version": 1,
        "error": "X-PAYMENT header is required",
        "accepts": [
            {
                "scheme": "exact",
                "network": "base-sepolia",
                "maxAmountRequired": "1000",
                "resource": "http://localhost:4021/weather",
                "description": "",
                "mimeType": "",
                "payTo": "0x023399dE1cd0bEc8d5603A3bDf350226ffe064EE",
                "maxTimeoutSeconds": 60,
                "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
                "extra": {
                    "name": "USDC",
                    "version": "2"
                }
            }
        ]
    }
  
  Visit this site for details about x402 protocol: https://www.x402.org/

@param[in] {BCHAR*} response_str
    The a string of Payment Request.

@return
  This function returns a pointer to struct tPaymentRequestInfo containing the\n
  parsed fields in the Payment Request.\n
  It returns NULL if error occurs.

*******************************************************************************/
tPaymentRequestInfo * x402ParsePaymentRequest(BCHAR *response_str)
{
    cJSON *cjson_accepts_ptr = NULL;
    cJSON *cjson_accepts_array_element_ptr;

    const char *cjson_error_ptr = NULL;

    tPaymentRequestInfo * payment_request_info_ptr = NULL;

    boat_try_declare;

    if(response_str == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Response String cannot be NULL.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    // Prepare return object
    payment_request_info_ptr = BoatMalloc(sizeof(tPaymentRequestInfo));
    if (payment_request_info_ptr == NULL)
    {
		BoatLog(BOAT_LOG_NORMAL, "Out of memory.");
		boat_throw(BOAT_ERROR_COMMON_OUT_OF_MEMORY, cleanup);
    }


    // Convert response to cJSON
	payment_request_info_ptr->cjson_http_response_ptr = cJSON_Parse(response_str);
	if (payment_request_info_ptr->cjson_http_response_ptr == NULL)
    {
        cjson_error_ptr = cJSON_GetErrorPtr();
        if (cjson_error_ptr != NULL)
        {
            BoatLog(BOAT_LOG_NORMAL, "Parsing RESPONSE as JSON fails before: %s.", cjson_error_ptr);
        }
        boat_throw(BOAT_ERROR, cleanup);
    }

    // Obtain "accepts" object
	cjson_accepts_ptr = cJSON_GetObjectItem(payment_request_info_ptr->cjson_http_response_ptr, "accepts");
	if (cjson_accepts_ptr == NULL)
	{
		BoatLog(BOAT_LOG_NORMAL, "Cannot find \"accepts\" item in RESPONSE.");
		boat_throw(BOAT_ERROR, cleanup);
	}

    // the "accepts" item must be an array
	if (!cJSON_IsArray(cjson_accepts_ptr))
	{
		BoatLog(BOAT_LOG_NORMAL, "\"accepts\" item is not an array.");
		boat_throw(BOAT_ERROR, cleanup);
	}

    BSINT32 accepts_array_size;
    accepts_array_size = cJSON_GetArraySize(cjson_accepts_ptr);

    if(accepts_array_size < 1)
    {
		BoatLog(BOAT_LOG_NORMAL, "Empty \"accepts\" array with size of %d.", accepts_array_size);
		boat_throw(BOAT_ERROR, cleanup);
    }
    else if(accepts_array_size > 1)
    {
        BoatLog(BOAT_LOG_NORMAL, "WARNING: \"accepts\" array size is %d. All elements other than the first one will be ignored.", accepts_array_size);
    }

    // Pick up the first element of "accepts" array
    cjson_accepts_array_element_ptr = cJSON_GetArrayItem(cjson_accepts_ptr, 0);
    if(cjson_accepts_array_element_ptr == NULL)
    {
		BoatLog(BOAT_LOG_NORMAL, "Fail to retrieve \"accepts[0]\".");
		boat_throw(BOAT_ERROR, cleanup);
    }


    // The accepts element must be an object
   	if (!cJSON_IsObject(cjson_accepts_array_element_ptr))
	{
		BoatLog(BOAT_LOG_NORMAL, "\"accepts[0]\" item is not an object.");
		boat_throw(BOAT_ERROR, cleanup);
	}

    // Obtain network item
    boat_try(getStringFromcJson(&payment_request_info_ptr->network_str, cjson_accepts_array_element_ptr, "network"));

    // Obtain maxAmountRequired item
    boat_try(getStringFromcJson(&payment_request_info_ptr->amount_str, cjson_accepts_array_element_ptr, "maxAmountRequired"));

    // Obtain resource item
    boat_try(getStringFromcJson(&payment_request_info_ptr->resource_str, cjson_accepts_array_element_ptr, "resource"));

    // Obtain payTo item
    boat_try(getStringFromcJson(&payment_request_info_ptr->payTo_str, cjson_accepts_array_element_ptr, "payTo"));

    // Obtain maxTimeoutSeconds item
    boat_try(getNumberFromcJson(&payment_request_info_ptr->timeout_s32, NULL, cjson_accepts_array_element_ptr, "maxTimeoutSeconds"));

    // Obtain asset item
    boat_try(getStringFromcJson(&payment_request_info_ptr->asset_str, cjson_accepts_array_element_ptr, "asset"));



    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);

        if(payment_request_info_ptr != NULL)
        {
            if(payment_request_info_ptr->cjson_http_response_ptr != NULL)     cJSON_Delete(payment_request_info_ptr->cjson_http_response_ptr);
            BoatFree(payment_request_info_ptr);

            payment_request_info_ptr = NULL;
        }
    }

    return payment_request_info_ptr;
}




/*!*****************************************************************************
@brief Conduct x402 demo procedure

@details
  This function conducts a x402 interaction procedure:
  
  1. The client sends a normal HTTP Get Request without X-Payment Header. The
     x402 server should reply with Status Code 402 and the exact Payment Request.
  2. The client parses the Payment Request returned by the x402 server.
  3. The client conducts the Payment Payload and signs it.
  4. The client sends a HTTP Get Request with X-Payment Header. The x402 server
     should reply with the requested resources and an X-PAYMENT-RESPONSE in
     header.
  
  Visit this site for details about x402 protocol: https://www.x402.org/

@param[in] {BoatEthWallet*} ethereum_wallet_ptr
    The wallet object of the device. It's used to sign the Payment Payload.

@return
  This function returns BOAT_SUCCESS if the demo is successful.\n
  Otherwize an error code is returned.

*******************************************************************************/
BOAT_RESULT x402Process(BoatEthWallet *ethereum_wallet_ptr)
{
    BCHAR *response_str = NULL;
    BUINT32 response_len = 0;
    BOAT_RESULT result = BOAT_ERROR;

    tPaymentRequestInfo *payment_request_info_ptr = NULL; 
    BUINT8 typed_data_hash[32];
    BUINT8 nonce_u256[32];

    BCHAR *payment_payload_str = NULL;

    boat_try_declare;

    result = HttpClientInit();
    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_CRITICAL, "HTTP initialization failed.");
        boat_throw(BOAT_ERROR, cleanup);
    }

    // Make first GET without X-Payment
    result = HttpGetWithoutXPayment(g_x402_server_url,
                                   &response_str,
                                   &response_len);
    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_CRITICAL, "GET without X-Payment failed.");
        boat_throw(BOAT_ERROR, cleanup);
    }

    // Print HTTP Response
	BoatLog(BOAT_LOG_NORMAL, "GET without X-Payment Response:\n%s", response_str);

    // Parse Payment Request returned by x402 server
    payment_request_info_ptr = x402ParsePaymentRequest(response_str);

    if(payment_request_info_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Parsing Payment Request failed.");
        boat_throw(BOAT_ERROR, cleanup);
    }

    //// Calculate EIP-3009 Hash to sign

    BUINT64 validAfter_u64 = time(NULL) - 60;   // Minus 60 seconds to ensure it's "in the past" when
                                                // the EIP-3009 message arrives at the contract
    BUINT64 validBefore_u64 = validAfter_u64 + payment_request_info_ptr->timeout_s32 + 60;    // Seconds

    BoatRandom(nonce_u256, sizeof(nonce_u256), NULL);

    BCHAR payer_address_hex_str[sizeof(BoatAddress)*2 + 3];

    UtilityBinToHex(payer_address_hex_str,
                    ethereum_wallet_ptr->account_info.address,
                    sizeof(BoatAddress),
                    BIN2HEX_LEFTTRIM_UNFMTDATA,
                    BIN2HEX_PREFIX_0x_YES,
                    BOAT_FALSE);

    BoatLog(BOAT_LOG_NORMAL, "Payer Address: %s", payer_address_hex_str);

    result = makeEip3009Hash(typed_data_hash, payer_address_hex_str, payment_request_info_ptr, validAfter_u64, validBefore_u64, nonce_u256);

    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Calculating hash failed.");
        boat_throw(BOAT_ERROR, cleanup);
    }

    /***********************************************************************************************
        NOTE: EIP-712 (https://eips.ethereum.org/EIPS/eip-712) states v should be 1 byte and conform 
        to EIP-155. However, for any Chain ID >= 110, sizeof(v) will exceed 1 byte.
        This implementation follows non-EIP-155 rules (v = {27,28}) to conform to Coinbase Developer
        Platform's official x402 implementation of node_module.
    ***********************************************************************************************/

    BUINT8 signature[65]; // 0~31: r, 32~63: s, 64: v
    BUINT32 signature_len = sizeof(signature) - 1;  // minus 1 to reserve the last byte for v
    BUINT8 parity;


    result = BoAT_Keystore_Sign(ethereum_wallet_ptr->account_info.prikeyCtx.prikey_type,
                                ethereum_wallet_ptr->account_info.prikeyCtx.keypair_index,
                                typed_data_hash,
                                sizeof(typed_data_hash),
                                signature,
                                &signature_len,
                                &parity);
    if (result != BOAT_SUCCESS)
    {
		BoatLog(BOAT_LOG_NORMAL, "Calling BoAT_Keystore_Sign() failed.");
		boat_throw(BOAT_ERROR, cleanup);
    }

    signature[64] = parity + 27;  // v


    // Construct Payment Payload

    BCHAR signature_hex_str[sizeof(signature)*2 + 3];

    UtilityBinToHex(signature_hex_str,
                    signature,
                    sizeof(signature),
                    BIN2HEX_LEFTTRIM_UNFMTDATA,
                    BIN2HEX_PREFIX_0x_YES,
                    BOAT_FALSE);

    BCHAR nonce_hex_str[67];  // "0x" + 256-bit in HEX + '\0'

    UtilityBinToHex(nonce_hex_str,
                    nonce_u256,
                    32,
                    BIN2HEX_LEFTTRIM_UNFMTDATA,
                    BIN2HEX_PREFIX_0x_YES,
                    BOAT_FALSE);


    #define PAYMENT_PAYLOAD_STRING_BUF_SIZE 1024
    payment_payload_str = BoatMalloc(PAYMENT_PAYLOAD_STRING_BUF_SIZE);
    if (payment_payload_str == NULL)
    {
		BoatLog(BOAT_LOG_NORMAL, "Out of memory.");
		boat_throw(BOAT_ERROR_COMMON_OUT_OF_MEMORY, cleanup);
    }

    snprintf(   payment_payload_str,
                PAYMENT_PAYLOAD_STRING_BUF_SIZE,
                "{"
                    "\"x402Version\":1,"
                    "\"scheme\":\"exact\","
                    "\"network\": \"%s\","
                    "\"payload\": {"
                        "\"signature\": \"%s\","
                        "\"authorization\": {"
                            "\"from\": \"%s\","
                            "\"to\": \"%s\","
                            "\"value\": \"%s\","
                            "\"validAfter\": \"%llu\","
                            "\"validBefore\": \"%llu\","
                            "\"nonce\": \"%s\""
                        "}"
                    "}"
                "}",
                payment_request_info_ptr->network_str,
                signature_hex_str,
                payer_address_hex_str,
                payment_request_info_ptr->payTo_str,
                payment_request_info_ptr->amount_str,
                validAfter_u64,
                validBefore_u64,
                nonce_hex_str
            );

    BoatLog(BOAT_LOG_VERBOSE, "Payment Payload:\n%s", payment_payload_str);

    // Re-try HTTP GET with X-Payment
    result = HttpGetWithXPayment(payment_request_info_ptr->resource_str,
                                 payment_payload_str,
                                 &response_str,
                                 &response_len);

    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_CRITICAL, "GET with X-Payment failed.");
        boat_throw(BOAT_ERROR, cleanup);
    }

    // Print HTTP Response
	BoatLog(BOAT_LOG_NORMAL, "x402 X-Payment responds successfully with:\n%s", response_str);

    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    if(payment_request_info_ptr != NULL)
    {
        if(payment_request_info_ptr->cjson_http_response_ptr != NULL)     cJSON_Delete(payment_request_info_ptr->cjson_http_response_ptr);
        BoatFree(payment_request_info_ptr);
    }

    if(payment_payload_str != NULL)
    {
        BoatFree(payment_payload_str);
    }

    HttpClientDeinit();

    return result;
}


/*!*****************************************************************************
@brief Entry for the x402 demo

@details
  This function prepares necessary resources and starts the x402 process demo.
  It should be called from main().

  This function doesn't take any parameter.
  

@return
  This function returns BOAT_SUCCESS if the demo is successful.\n
  Otherwize it returns an error code.

*******************************************************************************/
BOAT_RESULT x402DemoEntry(void)
{
    BOAT_RESULT result;

    boat_try_declare;

    //// BoAT Inintialization
    
     /* Boat SDK initialization */
    BoatIotSdkInit();


    /* Create Ethereum-compatible Network
       (Not useful for x402 scenario, but keep for standard BoAT initialization procedure) */
    BoatLog(BOAT_LOG_NORMAL,"Creating Ethereum-compatible network");
    result = createEthereumNetwork();
    if (result != BOAT_SUCCESS)
	{
		BoatLog(BOAT_LOG_CRITICAL, "Creating Ethereum-compatible network failed: %d.", result);
	    boat_throw(BOAT_ERROR, cleanup);
	}


    /* Create ethereum wallet */
    BoatLog(BOAT_LOG_NORMAL, "Creating keypair.");
    result = ethereum_createKeypair(g_payer_key, "keypair00");
    if (result != BOAT_SUCCESS)
	{
		BoatLog(BOAT_LOG_CRITICAL, "Creating keypair failed: %d.", result);
		boat_throw(BOAT_ERROR, cleanup);
	}

    /* Initialize ethereum wallet */
    BoatLog(BOAT_LOG_NORMAL,"Initializing wallet");
    g_ethereum_wallet_ptr = BoatEthWalletInit(g_keypairIndex, g_networkIndex);
    if(g_ethereum_wallet_ptr == NULL){
        BoatLog(BOAT_LOG_NORMAL,"BoatEthWalletInit fail");
        boat_throw(BOAT_ERROR, cleanup);
    }

    boat_try(x402Process(g_ethereum_wallet_ptr));

    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    /* Boat SDK Deinitialization */
    if(g_ethereum_wallet_ptr != NULL)   BoatEthWalletDeInit(g_ethereum_wallet_ptr);
    BoatIotSdkDeInit();

    return(result);
}
