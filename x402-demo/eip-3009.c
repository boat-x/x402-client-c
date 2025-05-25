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

#include <stdio.h>
#include <string.h>

#include "x402-demo.h"
#include "boat_keystore_intf.h"


BOAT_RESULT makeHashEip3009TransferAuth(BOAT_OUT BUINT8 typed_data_hash_out[32], const BCHAR *domain_separator_str, const BCHAR *from_str, const BCHAR *to_str, BUINT64 value_u64, BUINT64 validAfter_u64, BUINT64 validBefore_u64, BUINT8 nonce_u256[32])
{
    BOAT_RESULT result = BOAT_SUCCESS;
    BUINT8 hashStruct_eip3009[32];

    // EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH defined at https://eips.ethereum.org/EIPS/eip-3009
    const BUINT8  EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH [32] = {0x7c, 0x7c, 0x6c, 0xdb, 0x67, 0xa1, 0x87, 0x43, 0xf4, 0x9e, 0xc6, 0xfa, 0x9b, 0x35, 0xf5, 0x0d, 0x52, 0xed, 0x05, 0xcb, 0xed, 0x4c, 0xc5, 0x92, 0xe1, 0x3b, 0x44, 0x50, 0x1c, 0x1a, 0x22, 0x67};

    BUINT32 eip3009_msg_len;
    BUINT8 *eip3009_msg_plus_typeHash_ptr = NULL;
    BUINT8 *eip712_typed_data_ptr = NULL;
    BUINT32 offset;

    BUINT32 hex_len;
    BUINT8 uint256_array[32];


    BUINT8 abi_encoded_uint160_from[32];
    BUINT8 abi_encoded_uint160_to[32];
    BUINT8 abi_encoded_uint256_value[32];
    BUINT8 abi_encoded_uint256_validAfter[32];
    BUINT8 abi_encoded_uint256_validBefore[32];
    BUINT8 abi_encoded_bytes32_nonce[32];

    boat_try_declare;

    // Check function arguments
    if (    typed_data_hash_out == NULL
         || domain_separator_str == NULL
         || from_str == NULL
         || to_str == NULL
         || validAfter_u64 > validBefore_u64 )
    {
        BoatLog(BOAT_LOG_CRITICAL, "Invalid Parameter.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }


    ////////////// Prepare hashStruct(message) ////////////////

    // Initialize EIP-3009 message length
    eip3009_msg_len = 0;

    // Encode "from address"

    // Convert from_str to 160-bit address. Address is treated as uint160 and left-padded with zeros to 256 bits
    memset(abi_encoded_uint160_from, 0x00, 32);
    hex_len = UtilityHexToBin(&abi_encoded_uint160_from[12], sizeof(BoatAddress), from_str, TRIMBIN_TRIM_NO, BOAT_FALSE);
    if( hex_len != sizeof(BoatAddress))
    {
        BoatLog(BOAT_LOG_CRITICAL, "Incorrect \"from\" address format.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    // Encode "to address"

    // Convert to_str to 160-bit address. Address is treated as uint160 and left-padded with zeros to 256 bits
    memset(abi_encoded_uint160_to, 0x00, 32);
    hex_len = UtilityHexToBin(&abi_encoded_uint160_to[12], sizeof(BoatAddress), to_str, TRIMBIN_TRIM_NO, BOAT_FALSE);
    if( hex_len != sizeof(BoatAddress))
    {
        BoatLog(BOAT_LOG_CRITICAL, "Incorrect \"to\" address format.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    // Encode "value"

    // Convert value from little endian uint64 to big endian uint256 and place
    // it at the 24th position of encoded 256-bit ABI field with leading zeros.
    memset(abi_encoded_uint256_value, 0x00, 32);
    UtilityUint64ToBigend(&abi_encoded_uint256_value[24], value_u64, TRIMBIN_TRIM_NO);

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    //Encode "validAfter"

    // Convert validAfter from little endian uint64 to big endian uint256 and place
    // it at the 24th position of encoded 256-bit ABI field with leading zeros.
    memset(abi_encoded_uint256_validAfter, 0x00, 32);
    UtilityUint64ToBigend(&abi_encoded_uint256_validAfter[24], validAfter_u64, TRIMBIN_TRIM_NO);

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    // Encode "validBefore"

    // Convert validBefore from little endian uint64 to big endian uint256 and place
    // it at the 24th position of encoded 256-bit ABI field with leading zeros.
    memset(abi_encoded_uint256_validBefore, 0x00, 32);
    UtilityUint64ToBigend(&abi_encoded_uint256_validBefore[24], validBefore_u64, TRIMBIN_TRIM_NO);

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    // Encode "nonce"

    memcpy(abi_encoded_bytes32_nonce, nonce_u256, 32);

    eip3009_msg_len += 32;  // ABI encoding for static types is always 256 bits long.


    // Concatenate EIP-3009 message with typeHash

    eip3009_msg_plus_typeHash_ptr = BoatMalloc(  sizeof(EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH)   // typeHash
                                               + eip3009_msg_len);                                      // EIP-3009 message

    if(eip3009_msg_plus_typeHash_ptr == NULL)
    {
        BoatLog(BOAT_LOG_VERBOSE, "Out of memory.");
        boat_throw(BOAT_ERROR_COMMON_OUT_OF_MEMORY, cleanup);
    }

    offset = 0;

    // Concatenate typeHash and messsage
    memcpy(eip3009_msg_plus_typeHash_ptr + offset, EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH, sizeof(EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH));
    offset += sizeof(EIP3009_TRANSFER_WITH_AUTHORIZATION_TYPEHASH);
    
    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_uint160_from, 32);
    offset += 32;

    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_uint160_to, 32);
    offset += 32;

    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_uint256_value, 32);
    offset += 32;

    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_uint256_validAfter, 32);
    offset += 32;

    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_uint256_validBefore, 32);
    offset += 32;

    memcpy(eip3009_msg_plus_typeHash_ptr + offset, abi_encoded_bytes32_nonce, 32);
    offset += 32;

    // Print EIP-3009 message fields
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"from\"", abi_encoded_uint160_from, 32);
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"to\"", abi_encoded_uint160_to, 32);
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"value\"", abi_encoded_uint256_value, 32);
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"validAfter\"", abi_encoded_uint256_validAfter, 32);
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"validBefore\"", abi_encoded_uint256_validBefore, 32);
    BoatLog_hexdump(BOAT_LOG_VERBOSE, "ABI Encoded \"nonce\"", abi_encoded_bytes32_nonce, 32);

    // Calculate keccak256 of eip3009_msg_plus_typeHash_ptr
    
    result = BoatHash(BOAT_HASH_KECCAK256, eip3009_msg_plus_typeHash_ptr, offset, hashStruct_eip3009, NULL, NULL);

    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_VERBOSE, "Hashing failed.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }


    // Concatenate TypedData to calculate hash

    eip712_typed_data_ptr = BoatMalloc(  2      // {0x19, 0x01}
                                       + 32     // EIP-3009 domainSeparator
                                       + 32);   // hashStruct(EIP-3009 message)

    if(eip712_typed_data_ptr == NULL)
    {
        BoatLog(BOAT_LOG_VERBOSE, "Out of memory.");
        boat_throw(BOAT_ERROR_COMMON_OUT_OF_MEMORY, cleanup);
    }

    offset = 0;

    // Concatenate {0x19, 0x01} leading bytes
    eip712_typed_data_ptr[offset++] = 0x19;
    eip712_typed_data_ptr[offset++] = 0x01;

    // Concatenate domainSeparator
    // Convert domain_separator_str to u256
    hex_len = UtilityHexToBin(uint256_array, sizeof(uint256_array), domain_separator_str, TRIMBIN_TRIM_NO, BOAT_FALSE);
    if( hex_len != sizeof(uint256_array))
    {
        BoatLog(BOAT_LOG_CRITICAL, "Incorrect \"domainSeparator\" format.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }

    memcpy(eip712_typed_data_ptr + offset, uint256_array, sizeof(uint256_array));
    offset += sizeof(uint256_array);

    // Concatenate hashStruct(EIP-3009 message)
    memcpy(eip712_typed_data_ptr + offset, hashStruct_eip3009, sizeof(hashStruct_eip3009));
    offset += sizeof(hashStruct_eip3009);


    // Calculate keccak256 of EIP-712 typedData
 
    result = BoatHash(BOAT_HASH_KECCAK256, eip712_typed_data_ptr, offset, typed_data_hash_out, NULL, NULL);

    if(result != BOAT_SUCCESS)
    {
        BoatLog(BOAT_LOG_VERBOSE, "Hashing failed.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }


    // Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    return result;
}


BOAT_RESULT makeEip3009TypedHash(BOAT_OUT BUINT8 typed_data_hash_out[32], const BCHAR *payer_address_str, const tPaymentRequestInfo * payment_request_info_ptr, BUINT64 validAfter_u64, BUINT64 validBefore_u64, BUINT8 nonce_u256[32])
{
    BCHAR *domain_separator_str;
    BOAT_RESULT result = BOAT_ERROR;

    boat_try_declare;

    if(payment_request_info_ptr == NULL)
    {
        BoatLog(BOAT_LOG_CRITICAL, "Payment Request cannot be NULL.");
        boat_throw(BOAT_ERROR_COMMON_INVALID_ARGUMENT, cleanup);
    }


    // domainSearator
    // Base mainnet (https://basescan.org/address/0x2ce6311ddae708829bc0784c967b7d77d19fd779#readContract):
    BCHAR *domain_separator_base_mainnet = "0x0ecb934f6b324378a67dfd8d23a12049612af51005a1880f784e747d995b75c6";
    // Base Sepolia (https://base-sepolia.blockscout.com/token/0x036CbD53842c5426634e7929541eC2318f3dCF7e?tab=read_proxy):
    BCHAR *domain_separator_base_sepolia =  "0x71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818";
    
    if(strcmp(payment_request_info_ptr->network_str, "base") == 0)
    {
        domain_separator_str = domain_separator_base_mainnet;
    }
    else if(strcmp(payment_request_info_ptr->network_str, "base-sepolia") == 0)
    {
        domain_separator_str = domain_separator_base_sepolia;
    }
    else
    {
		BoatLog(BOAT_LOG_NORMAL, "Unknown network: %s.", payment_request_info_ptr->network_str);
		boat_throw(BOAT_ERROR, cleanup);
    }
    
    errno = 0;
    BUINT64 amount = strtoll(payment_request_info_ptr->amount_str, NULL, 0);   // Unit: 1E-6 USDC
    if((errno == ERANGE && (amount == LLONG_MAX || amount == LLONG_MIN)) || (errno != 0 && amount == 0))
    {
		BoatLog(BOAT_LOG_NORMAL, "Invalid maxAmountRequired: %s.", payment_request_info_ptr->amount_str);
		boat_throw(BOAT_ERROR, cleanup);
    }


    result = makeHashEip3009TransferAuth(typed_data_hash_out,
                                         domain_separator_str,
                                         payer_address_str,
                                         payment_request_info_ptr->payTo_str,
                                         amount,
                                         validAfter_u64,
                                         validBefore_u64,
                                         nonce_u256);

    if (result != BOAT_SUCCESS)
    {
		BoatLog(BOAT_LOG_NORMAL, "Calling MakeHashEip3009TransferAuth() failed.");
		boat_throw(BOAT_ERROR, cleanup);
    }

    // Exceptional Clean Up
    boat_catch(cleanup)
    {
        BoatLog(BOAT_LOG_NORMAL, "Exception: %d", boat_exception);
        result = boat_exception;
    }

    return result;

}

