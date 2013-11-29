/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <resolv.h>
#include <unistd.h>
#include <sys/time.h>
#include <curl/curl.h>

#define LOG_TAG "OEMListener"
#define DBG 1

#include <cutils/log.h>
#include <sysutils/SocketClient.h>

extern "C" int system_nosh ( const char *command );

#include "OEMListener.h"

extern "C"
{
    struct MemoryStruct
    {
        char *memory;
        size_t size;
    };

    void* pthread_forward ( void* obj )
    {
        OEMListener* oemObj = reinterpret_cast<OEMListener*> ( obj );
        oemObj->SrvrFunction();
        pthread_exit ( NULL );
        return 0;
    }

    size_t WriteMemoryCallback ( void *contents, size_t size, size_t nmemb, void *userp )
    {
        size_t realsize = size * nmemb;
        struct MemoryStruct *mem = ( struct MemoryStruct * ) userp;

        mem->memory = ( char* ) realloc ( mem->memory, mem->size + realsize + 1 );
        if ( mem->memory == NULL )
        {
            /* out of memory! */
            LOGE ( " ## ## WriteMemoryCallback not enough memory (realloc returned NULL)\n" );
            return 0;
        }

        memcpy ( & ( mem->memory[mem->size] ), contents, realsize );
        mem->size += realsize;
        mem->memory[mem->size] = 0;

        return realsize;
    }
}

const char OEMListener::INTERFACE[] = "ppp0";
const char OEMListener::IPTABLES_PATH[] = "/system/bin/iptables";
const char OEMListener::IP6TABLES_PATH[] = "/system/bin/ip6tables";


OEMListener::OEMListener()
{
    int srvrRet;
    if ( ( srvrRet = pthread_create ( &mSrvrThread, NULL, pthread_forward, this ) ) )
    {
        LOGE ( " ## ## OEMListener ctor: Thread creation failed: %d", srvrRet );
        return;
    }
}

void OEMListener::SrvrFunction()
{

    CURL *curl = NULL;
    CURLcode res;
    char *postrequest = NULL;
    char *response = NULL;
    struct MemoryStruct chunk;
    struct MemoryStruct bodyChunk;

    int reslt = 0;
    std::string fullCmd4;
    std::string fullCmd6;

    FILE *iptOutput;
    char line[256];
    memset ( line,0, sizeof line );
    fullCmd4.clear();
    fullCmd4.append ( IPTABLES_PATH );
    fullCmd4.append ( " -nL OUTPUT" );
    bool found_oemhook = false;
    int oemhookcounter = 0;
    while ( ( !found_oemhook ) && oemhookcounter < 120 )
    {
        iptOutput = popen ( fullCmd4.c_str(), "r" );
        if ( !iptOutput )
        {
            LOGE ( " ## ## Failed to run %s err=%s", fullCmd4.c_str(), strerror ( errno ) );
            oemhookcounter++ ;
            usleep ( 5000000 );
            continue;
        }

        std::string allfpipe;

        while ( fgets ( line, sizeof line, iptOutput ) )
        {
            allfpipe.append ( line );
        }

        pclose ( iptOutput );

        std::size_t found_oem_out = allfpipe.find ( "globalAlert" );
        if ( found_oem_out != std::string::npos )
        {
            found_oemhook = true;
            break;
        }
        else
        {
            LOGE ( " ## ## Failed to find oemhook " );
        }

        oemhookcounter++ ;
        usleep ( 5000000 );
    }


    if ( found_oemhook )
    {
        // insha2 sinsli p30dw
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -N p30dw" );
        reslt = system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( " -N p30dw" );
        reslt = system_nosh ( fullCmd6.c_str() );

        // idkhal al-rafid bi sinsli p30dw
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -A p30dw --jump REJECT --reject-with icmp-net-prohibited" );
        reslt |= system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( "  -A p30dw --jump REJECT --reject-with icmp6-adm-prohibited" );
        reslt |= system_nosh ( fullCmd6.c_str() );

        // idkhal sinsli p30dw bi sinsli INPUT
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -I INPUT 2 -i " );
        fullCmd4.append ( INTERFACE );
        fullCmd4.append ( " --goto p30dw" );
        reslt |= system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( "  -I INPUT 2 -i " );
        fullCmd6.append ( INTERFACE );
        fullCmd6.append ( " --goto p30dw" );
        reslt |= system_nosh ( fullCmd6.c_str() );


        // idkhal sinsli p30dw bi sinsli OUTPUT
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -I OUTPUT 1 -o " );
        fullCmd4.append ( INTERFACE );
        fullCmd4.append ( " --goto p30dw" );
        reslt |= system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( "  -I OUTPUT 1 -o " );
        fullCmd6.append ( INTERFACE );
        fullCmd6.append ( " --goto p30dw" );
        reslt |= system_nosh ( fullCmd6.c_str() );

        return;

        if ( reslt == 0 )
        {
            chunk.memory = ( char* ) malloc ( 1 );
            chunk.size = 0;

            bodyChunk.memory = ( char* ) malloc ( 1 );
            bodyChunk.size = 0;

            asprintf ( &postrequest, "%s", "" );

            curl_global_init ( CURL_GLOBAL_ALL );
            curl = curl_easy_init();

            if ( curl )
            {
                curl_easy_setopt ( curl, CURLOPT_URL, "https://support.datawind-s.com/progserver/touchrequest.jsp" );
                curl_easy_setopt ( curl, CURLOPT_POSTFIELDS, postrequest );

                curl_easy_setopt ( curl, CURLOPT_NOPROGRESS, 1 );
                curl_easy_setopt ( curl, CURLOPT_VERBOSE, 0 );
                curl_easy_setopt ( curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback );
                curl_easy_setopt ( curl, CURLOPT_WRITEHEADER, ( void * ) &chunk );
                curl_easy_setopt ( curl,  CURLOPT_WRITEFUNCTION, WriteMemoryCallback );
                curl_easy_setopt ( curl, CURLOPT_WRITEDATA, ( void * ) &bodyChunk );
                curl_easy_setopt ( curl, CURLOPT_USERAGENT, "libcurl-agent/1.0" );

                res = curl_easy_perform ( curl );

                while ( ( res != CURLE_OK ) )
                {
                    ///FIXME: need to do something about this infinite looop!
                    usleep ( 50000000 );
                    res = curl_easy_perform ( curl );
                }

                asprintf ( &response,"%s",chunk.memory );

                /// got repond

                curl_easy_cleanup ( curl );

            }

            else
            {
                goto curl_failed;
            }
        }
    }


curl_failed:
    /*
        if ( chunk.memory )
            free ( chunk.memory );
        chunk.memory = NULL;
        if ( bodyChunk.memory )
            free ( bodyChunk.memory );
        bodyChunk.memory = NULL;

        if ( postrequest )
            free ( postrequest );
        postrequest = NULL;
        if ( response )
            free ( response );
        response = NULL;

        curl_global_cleanup();
        */
    return;

}



void OEMListener::wait_for_SrvrExit()
{
    pthread_join ( mSrvrThread, NULL );
}
