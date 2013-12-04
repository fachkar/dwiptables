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
#include <cerrno>
#include <cstring>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <cstdio>
#include <fstream>
#include <resolv.h>
#include <unistd.h>
#include <sys/time.h>
#include <curl/curl.h>
#include <zlib.h>
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


std::string OEMListener::DeflateString ( const std::string& str )
{
    int ret;
    char outbuffer[32768];
    std::string outstring;

    z_stream zs;                        // z_stream is zlib's control structure
    memset ( &zs, 0, sizeof ( zs ) );

    if ( inflateInit ( &zs ) != Z_OK )
    {
        LOGE ( " ## ## inflateInit failed while decompressing." );
        return outstring;
    }

    zs.next_in = ( Bytef* ) str.data();
    zs.avail_in = str.size();

    // get the decompressed bytes blockwise using repeated calls to inflate
    do
    {
        zs.next_out = reinterpret_cast<Bytef*> ( outbuffer );
        zs.avail_out = sizeof ( outbuffer );

        ret = inflate ( &zs, 0 );

        if ( outstring.size() < zs.total_out )
        {
            outstring.append ( outbuffer,
                               zs.total_out - outstring.size() );
        }

    }
    while ( ret == Z_OK );

    inflateEnd ( &zs );

    if ( ret != Z_STREAM_END )          // an error occurred that was not EOF
    {
        LOGE ( " ## ## Exception during zlib decompression: ( %d) %s\n", ret, zs.msg );
        return outstring;
    }

    return outstring;
}

int OEMListener::commonIpCmd ( std:: string cmd )
{
    int reslt;
    std::string fullCmd4, fullCmd6;

    fullCmd4.clear();
    fullCmd4.append ( IPTABLES_PATH );
    fullCmd4.append ( cmd );
    reslt = system_nosh ( fullCmd4.c_str() );

    fullCmd6.clear();
    fullCmd6.append ( IP6TABLES_PATH );
    fullCmd6.append ( cmd );
    reslt = system_nosh ( fullCmd6.c_str() );

    return reslt;
}

int OEMListener::infStr ( FILE *source, std::string& rtrnStr )
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[1024];
    unsigned char out[1024];

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit ( &strm );
    if ( ret != Z_OK )
        return ret;

    /* decompress until deflate stream ends or end of file */
    do
    {
        strm.avail_in = fread ( in, 1, 1024, source );
        if ( ferror ( source ) )
        {
            ( void ) inflateEnd ( &strm );
            return Z_ERRNO;
        }
        if ( strm.avail_in == 0 )
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do
        {
            strm.avail_out = 1024;
            strm.next_out = out;
            ret = inflate ( &strm, Z_NO_FLUSH );
            if ( ret == Z_STREAM_ERROR )
                return Z_ERRNO;  /* state not clobbered */
            switch ( ret )
            {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                ( void ) inflateEnd ( &strm );
                return ret;
            }
            have = 1024 - strm.avail_out;
            std::string tmpStr ( out, out + have );
            rtrnStr.append ( tmpStr );

        }
        while ( strm.avail_out == 0 );

        /* done when inflate() says it's done */
    }
    while ( ret != Z_STREAM_END );

    /* clean up and return */
    ( void ) inflateEnd ( &strm );
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

void OEMListener::SrvrFunction()
{

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

        std::size_t found_oem_out = allfpipe.find ( "p30dw" );
        if ( found_oem_out != std::string::npos )
        {
            found_oemhook = true;
            break;
        }

        oemhookcounter++ ;
        usleep ( 5000000 );
    }


    if ( found_oemhook )
    {
        // insha2 sinsli p30_1000
        reslt |= commonIpCmd ( " -N p30_1000" );

        // idkhal 1000 wa 10020 bi sinsli p30dw
        reslt |= commonIpCmd ( " -A p30dw -m owner --uid-owner 1000 --jump p30_1000" );

        reslt |= commonIpCmd ( " -A p30dw -m owner --uid-owner 10020 --jump p30_1000" );

        reslt |= commonIpCmd ( " -A p30dw -p udp --sport 53 -j ACCEPT" );

        reslt |= commonIpCmd ( " -A p30dw -p udp --dport 53 -j ACCEPT" );

        // idkhal al-rafid bi sinsli p30dw
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -A p30dw --jump REJECT --reject-with icmp-net-prohibited" );
        reslt |= system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( " -A p30dw --jump REJECT --reject-with icmp6-adm-prohibited" );
        reslt |= system_nosh ( fullCmd6.c_str() );

        // idkhal shurut p30_1000
        fullCmd4.clear();
        fullCmd4.append ( IPTABLES_PATH );
        fullCmd4.append ( " -A p30_1000 -m quota2 ! --quota 102400 --name p30_1000 --jump REJECT --reject-with icmp-net-prohibited" );
        reslt |= system_nosh ( fullCmd4.c_str() );

        fullCmd6.clear();
        fullCmd6.append ( IP6TABLES_PATH );
        fullCmd6.append ( " -A p30_1000 -m quota2 ! --quota 102400 --name p30_1000 --jump REJECT --reject-with icmp6-adm-prohibited" );
        reslt |= system_nosh ( fullCmd6.c_str() );

        reslt |= commonIpCmd ( " -A p30_1000 --jump ACCEPT" );

        if ( reslt == 0 )
        {
            // shouf pckg lst
            bool found_pckglst = false;
            int pckglstcounter = 0;
            while ( ( !found_pckglst ) && pckglstcounter < 120 )
            {
                FILE * pPckglstFile;
                pPckglstFile = fopen ( "/data/system/packages.list" , "r" );
                if ( pPckglstFile != NULL )
                {
                    char tmpline[512];

                    while ( fgets ( tmpline, sizeof ( tmpline ), pPckglstFile ) )
                    {
                        tmpline[strlen ( tmpline )-1] = '\0';
                        char pckgname[128] = {'\0'};
                        unsigned int pckguid = 0;
                        int sscanfrslt = 0;
                        sscanfrslt = sscanf ( tmpline,"%s %u", pckgname, &pckguid );
                        if ( sscanfrslt != 2 )
                        {
                            memset ( tmpline, '\0', 512 );
                            continue;
                        }

                        PckgObj tmpPckgObj ( pckgname,pckguid );
                        mPckgObjLst.push_back ( tmpPckgObj );

                        memset ( tmpline, '\0', 512 );
                    }

                    fclose ( pPckglstFile );

                    found_pckglst = true;
                    break;
                }


                pckglstcounter++ ;
                usleep ( 5000000 );
            }


            if ( found_pckglst )
            {
                // check current quotas
                FILE * pQtaRegFile;
                pQtaRegFile = fopen ( "/data/system/qtareg" , "rb" );
                if ( pQtaRegFile != NULL )
                {
                    std::string tmpDestStro;
                    int ret = infStr ( pQtaRegFile, tmpDestStro );
                    if ( ret != Z_OK )
                        LOGE ( " ## ## zlib error" );
                    fclose ( pQtaRegFile );

                    size_t foundn = tmpDestStro.find ( "\n" );
                    while ( foundn != std::string::npos )
                    {
                        std::string line;
                        line.assign ( tmpDestStro,0,foundn );
                        unsigned long pckguid = 0;
                        unsigned long long pckgqta = 0;
                        int sscanfrslt = 0;
                        sscanfrslt = sscanf ( line.c_str(),"%lu %llu", &pckguid, &pckgqta );
                        if ( sscanfrslt == 2 )
                        {
                            std::list<PckgObj>::iterator it;
                            for ( it = mPckgObjLst.begin(); it != mPckgObjLst.end(); ++it )
                            {
                                if ( it->uid == pckguid )
                                {
                                    it->clq = pckgqta;
                                    it->status = 1;

                                    // insha2 sinsli p30_xxx
                                    char *snisliname = NULL;
                                    asprintf(&snisliname, "%lu", pckguid);
                                    std::string snisliUidStr(snisliname);
                                    if(snisliname)
                                        free(snisliname);
                                    snisliname = NULL;

                                    asprintf(&snisliname, "%llu", pckgqta);

                                    std::string snisliQuotaStr(snisliname);
                                    if(snisliname)
                                        free(snisliname);
                                    snisliname = NULL;

                                    reslt |= commonIpCmd ( " -N p30_" + snisliUidStr );

                                    fullCmd4.clear();
                                    fullCmd4.append ( IPTABLES_PATH );
                                    fullCmd4.append ( " -A p30_" + snisliUidStr + " -m quota2 ! --quota " + snisliQuotaStr + " --name p30_" + snisliUidStr + " --jump REJECT --reject-with icmp-net-prohibited" );
                                    reslt |= system_nosh ( fullCmd4.c_str() );

                                    fullCmd6.clear();
                                    fullCmd6.append ( IP6TABLES_PATH );
                                    fullCmd6.append ( " -A p30_" + snisliUidStr + " -m quota2 ! --quota " + snisliQuotaStr + " --name p30_" + snisliUidStr + " --jump REJECT --reject-with icmp6-adm-prohibited" );
                                    reslt |= system_nosh ( fullCmd6.c_str() );

                                    reslt |= commonIpCmd ( "-A p30_" + snisliUidStr + " --jump ACCEPT" );

                                    reslt |= commonIpCmd ( "-A p30dw -m owner --uid-owner " + snisliUidStr + " --jump p30_" + snisliUidStr );


                                }
                            }
                        }
                        line.assign ( tmpDestStro, foundn +1 , tmpDestStro.size() - line.size() - 1 );
                        tmpDestStro.assign ( line );
                        foundn = tmpDestStro.find ( "\n" );
                    }

                }

            }


//             CURL *curl = NULL;
//             CURLcode res;
//             char *postrequest = NULL;
//             char *response = NULL;
//             struct MemoryStruct chunk;
//             struct MemoryStruct bodyChunk;
//             chunk.memory = ( char* ) malloc ( 1 );
//             chunk.size = 0;
//
//             bodyChunk.memory = ( char* ) malloc ( 1 );
//             bodyChunk.size = 0;
//
//             asprintf ( &postrequest, "%s", "" );
//
//             curl_global_init ( CURL_GLOBAL_ALL );
//             curl = curl_easy_init();
//
//             if ( curl )
//             {
//                 curl_easy_setopt ( curl, CURLOPT_URL, "https://support.datawind-s.com/progserver/touchrequest.jsp" );
//                 curl_easy_setopt ( curl, CURLOPT_POSTFIELDS, postrequest );
//
//                 curl_easy_setopt ( curl, CURLOPT_NOPROGRESS, 1 );
//                 curl_easy_setopt ( curl, CURLOPT_VERBOSE, 0 );
//                 curl_easy_setopt ( curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback );
//                 curl_easy_setopt ( curl, CURLOPT_WRITEHEADER, ( void * ) &chunk );
//                 curl_easy_setopt ( curl,  CURLOPT_WRITEFUNCTION, WriteMemoryCallback );
//                 curl_easy_setopt ( curl, CURLOPT_WRITEDATA, ( void * ) &bodyChunk );
//                 curl_easy_setopt ( curl, CURLOPT_USERAGENT, "libcurl-agent/1.0" );
//
//                 res = curl_easy_perform ( curl );
//
//                 while ( ( res != CURLE_OK ) )
//                 {
//                     ///FIXME: need to do something about this infinite looop!
//                     usleep ( 50000000 );
//                     res = curl_easy_perform ( curl );
//                 }
//
//                 asprintf ( &response,"%s",chunk.memory );
//
//                 /// got repond
//
//                 curl_easy_cleanup ( curl );
//
//             }
//
//             else
//             {
//                 goto curl_failed;
//             }
        }
    }
    else
    {
        LOGE ( " ## ## Failed to find p30dw " );
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
