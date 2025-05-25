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

#ifdef USE_FIBOCOM_L718
#include "fibofwk.h"
#include "fibo_info_interface.h"
#include "fibo_mdc_interface.h"
#include "fibo_mrc_interface.h"
#include "fibo_sim_interface.h"
#include "fibo_mcc_interface.h"
#include "fibo_print.h"
#include "fibo_aps_interface.h"
#include "fibo_atClient_interface.h"
#include "fibo_atDefs_interface.h"


#include "fibo_semaphore.h"
#include "fibo_timer.h"
#include "fibo_print.h"
#include "fibo_http.h"
#endif

#include "curl/curl.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// Declaration

int x402DemoEntry(void);

#ifdef USE_FIBOCOM_L718
static fibo_mdc_ProfileRef_t g_profileRef = NULL;
#define DEFAULT_PROFILE_INDEX 1
//static fibo_mdc_ProfileRef_t profileRef = NULL;
static fibo_sem_Ref_t   waitSem = NULL;  
#endif


#ifdef USE_FIBOCOM_L718
int ActivateNetwork(void)
{
    
    // Check the current state of the cid
    fibo_mdc_ConState_t mdc_state = FIBO_MDC_DISCONNECTED;
    fibo_mrc_NetRegState_t mrc_state = FIBO_MRC_REG_UNKNOWN;
    fibo_result_t     res;
    char itfName[FIBO_MDC_INTERFACE_NAME_MAX_BYTES] = {0};
    char ipAddr[100] = {0};

    fibo_mdc_ConnectService();
    fibo_mrc_ConnectService();

    g_profileRef = fibo_mdc_GetProfile(DEFAULT_PROFILE_INDEX);
    if(!g_profileRef)
    {
        FIBO_INFO("fibo_mdc_GetProfile return NULL");
        return -1;
    }

    while(1)
    {
        res = fibo_mrc_GetNetRegState(&mrc_state);
        FIBO_INFO("fibo_mrc_GetNetRegState result:%s", FIBO_RESULT_TXT(res));

        if( res != FIBO_OK )
        {
            return -1;
        }
        else
        {
            if( mrc_state == FIBO_MRC_REG_HOME || mrc_state == FIBO_MRC_REG_ROAMING )
            {
                break;
            }
            else
            {
                sleep(5);
            }
            
        }
        
    }
    
   
    // Check the state
    res = fibo_mdc_GetSessionState(g_profileRef, &mdc_state);
    FIBO_INFO("fibo_mdc_GetSessionState state => %d, result:%s", mdc_state, FIBO_RESULT_TXT(res));
   
    // If already connected, disconnect the session
    if ( mdc_state == FIBO_MDC_CONNECTED )
    {
        res = fibo_mdc_StopSession(g_profileRef);
        FIBO_INFO("fibo_mdc_StopSession result:%s", FIBO_RESULT_TXT(res));
    }

    res = fibo_mdc_SetPDP(g_profileRef, FIBO_MDC_PDP_IPV4);
    FIBO_INFO("fibo_mdc_SetPDP result:%s", FIBO_RESULT_TXT(res));

    res = fibo_mdc_SetAPN(g_profileRef, "UNIM2M.NJM2MAPN");
    FIBO_INFO("fibo_mdc_SetAPN result:%s", FIBO_RESULT_TXT(res));

    res = fibo_mdc_StartSession(g_profileRef);
    FIBO_INFO("fibo_mdc_StartSession result:%s", FIBO_RESULT_TXT(res));

    return 0;
}


int DeactivateNetwork(void)
{
    fibo_result_t     res;
    int result = -1;

    res = fibo_mdc_StopSession(g_profileRef);
    FIBO_INFO("fibo_mdc_StopSession result:%s", FIBO_RESULT_TXT(res));

    fibo_mdc_DisconnectService();
    fibo_mrc_DisconnectService();


    if( res == FIBO_OK )    result = 0;
    else result = -1;

    return result;
}
#endif


int main(int argc, char *argv[])
{
    int result;

#ifdef USE_FIBOCOM_L718
    fibo_arg_SetArgs((size_t)argc, (char**)argv);
    setlinebuf(stdout);
    
    // Register the component with the Log Daemon.
    FIBO_INFO("uart test== Starting Executable '%s' ==", STRINGIZE(FIBO_EXECUTABLE_NAME));

    // Connect to the log control daemon.
    // Note that there are some rare cases where we don't want the
    // process to try to connect to the Log Control Daemon (e.g.,
    // the Supervisor and the Service Monitor shouldn't).
    // The NO_LOG_CONTROL macro can be used to control that.
#ifndef NO_LOG_CONTROL
        fibo_log_ConnectToControlDaemon();
#else
        FIBO_DEBUG("Not connecting to the Log Control Daemon.");
#endif
	curl_version_info_data *  civd = curl_version_info(CURLVERSION_FIRST);
    printf("\ncurl version: %s\n", civd->version);
    FIBO_INFO("Start oemDataTest");

	fibo_SetAppLimits(STRINGIZE(FIBO_EXECUTABLE_NAME));

	fibo_SetAppNotifyOnRelease(STRINGIZE(FIBO_EXECUTABLE_NAME));
    
    ActivateNetwork();

    fibo_atClient_ConnectService();
	//waitSem = fibo_sem_Create("WaitSignal",0);
#endif // End of #ifdef USE_FIBOCOM_L718

    // x402 Demo Entry    
    result = x402DemoEntry();


main_destruct:

#ifdef USE_FIBOCOM_L718
    fibo_atClient_DisconnectService();
    DeactivateNetwork();
#endif
    return result;
}
