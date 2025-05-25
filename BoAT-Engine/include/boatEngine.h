/**
****************************************************************************************
* @FilePath: boatEngine.h
* @Author: aitos
* @Date: 2023-02-27 20:58:14
* @LastEditors:
* @LastEditTime: 2023-02-27 20:58:14
* @Descripttion:
****************************************************************************************
*/
#ifndef __BOAT_ENGINE_H__
#define __BOAT_ENGINE_H__

#define BOAT_MAX_NETWORK_NUM 5

#include "persiststore.h"

//!@brief Blockchain Protocol types
typedef enum
{
    BOAT_PROTOCOL_UNKNOWN = 0, //!< Placeholder for unknown protocol
    BOAT_PROTOCOL_ETHEREUM,    //!< Ethereum
    BOAT_PROTOCOL_PLATON = 3,  //!< PlatON
    BOAT_PROTOCOL_QUORUM = 9,  //!< quorum
    BOAT_PROTOCOL_END
} BoatProtocolType;

#if PROTOCOL_USE_ETHEREUM == 1
#include "network/network_ethereum.h"
#include "protocolapi/api_ethereum.h"
#endif

#if PROTOCOL_USE_PLATON == 1
#include "network/network_platon.h"
#include "protocolapi/api_platon.h"
#endif







#if PROTOCOL_USE_QUORUM == 1
#include "network/network_quorum.h"
#include "protocolapi/api_quorum.h"
#endif


#endif
