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
#include <set>
#include <map>

#define LOG_TAG "OEMListener"
#define DBG 1

#include <cutils/log.h>
#include <cutils/properties.h>
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

    pthread_mutex_t count_mutex     = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  condition_var   = PTHREAD_COND_INITIALIZER;


    void* pthread_forward ( void* obj )
    {
        OEMListener* oemObj = reinterpret_cast<OEMListener*> ( obj );
        oemObj->SrvrFunction();
        pthread_exit ( NULL );
        return 0;
    }

    void* pthread_forward_count ( void* obj )
    {
        OEMListener* oemObj = reinterpret_cast<OEMListener*> ( obj );
        oemObj->CountFunction();
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
            LOGE ( " ## ## %s , not enough memory (realloc returned NULL)", __func__ );
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


OEMListener::OEMListener() :stopFuncs ( false ), prvUzlibdStr ( "" )
{
    int srvrRet;
    if ( ( srvrRet = pthread_create ( &mSrvrThread, NULL, pthread_forward, this ) ) )
    {
        LOGE ( " ## ## OEMListener ctor: Thread creation failed: %d", srvrRet );
        return;
    }

    if ( ( srvrRet = pthread_create ( &mCountThread, NULL, pthread_forward_count, this ) ) )
    {
        LOGE ( " ## ## OEMListener ctor: Thread creation failed: %d", srvrRet );
        return;
    }
}


int OEMListener::defStr ( std::string srcStr, FILE *dest )
{
    int ret, flush;
    unsigned have;
    z_stream strm;
    unsigned char in[1024];
    unsigned char out[1024];

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit ( &strm, Z_BEST_COMPRESSION );
    if ( ret != Z_OK )
        return ret;

    uInt rstOfStr = srcStr.size();
    char * srcStrPtr = const_cast<char*> ( srcStr.data() );
    /* compress until end of file */
    do
    {
        strm.avail_in = rstOfStr > 1024 ? 1024: rstOfStr;
        memcpy ( in, srcStrPtr, strm.avail_in );
        srcStrPtr += strm.avail_in;
        rstOfStr -= strm.avail_in;

        flush = ( strm.avail_in == 0 ) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        /* run deflate() on input until output buffer not full, finish
         *          compression if all of source has been read in */
        do
        {
            strm.avail_out = 1024;
            strm.next_out = out;
            ret = deflate ( &strm, flush ); /* no bad return value */
            if ( ret == Z_STREAM_ERROR ) /* state not clobbered */
            {
                LOGE ( " ## ## %s , state clobbered Z_STREAM_ERROR" , __func__ );
                return Z_STREAM_ERROR;
            }
            have = 1024 - strm.avail_out;
            if ( fwrite ( out, 1, have, dest ) != have || ferror ( dest ) )
            {
                ( void ) deflateEnd ( &strm );
                return Z_ERRNO;
            }
        }
        while ( strm.avail_out == 0 );

        /* done when last data in file processed */
    }
    while ( flush != Z_FINISH );
    if ( ret != Z_STREAM_END )
    {
        LOGE ( " ## ## %s , state clobbered Z_STREAM_END" , __func__ );
        return Z_STREAM_END;
    }

    /* clean up and return */
    ( void ) deflateEnd ( &strm );
    return Z_OK;
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
        LOGE ( " ## ## %s , inflateInit failed while decompressing." , __func__ );
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
        LOGE ( " ## ## %s , Exception during zlib decompression: ( %d) %s", __func__, ret, zs.msg );
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


void OEMListener::CountFunction()
{
    pthread_mutex_lock ( &count_mutex );
    pthread_cond_wait ( &condition_var, &count_mutex );
    usleep ( 50000000 );
    pthread_mutex_unlock ( &count_mutex );


    while ( !stopFuncs )
    {
        std::string tmpUzlibdStr;
        pthread_mutex_lock ( &count_mutex );

        for ( std::list<PckgObj>::iterator it = regPckgObjLst.begin(); it != regPckgObjLst.end(); ++it )
        {
            // have prv quota
            FILE *fp = NULL;
            char *fname = NULL;
            int rslt = 0;

            asprintf ( &fname, "/proc/net/xt_quota/p30_%u", it->gid );
            fp = fopen ( fname, "r" );
            if ( fname )
                free ( fname );
            fname = NULL;

            if ( fp != NULL )
            {
                unsigned long long tmpClq = 0;
                rslt = fscanf ( fp, "%llu", &tmpClq );
                fclose ( fp );

                it->clq = ( tmpClq>>10 );

                char * tmpStr = NULL;
                asprintf ( &tmpStr,"%s %u %u %llu,", it->package.c_str(), it->uid, it->gid, it->clq );
                tmpUzlibdStr.append ( tmpStr );
                if ( tmpStr )
                    free ( tmpStr );
                tmpStr = NULL;

            }
            else
            {
                char * tmpStr = NULL;
                asprintf ( &tmpStr,"%s %u %u %llu,", it->package.c_str(), it->uid, it->gid, it->clq );
                tmpUzlibdStr.append ( tmpStr );
                if ( tmpStr )
                    free ( tmpStr );
                tmpStr = NULL;
            }
        }

        pthread_mutex_unlock ( &count_mutex );

        if ( ( !tmpUzlibdStr.empty() ) && ( prvUzlibdStr.compare ( tmpUzlibdStr ) !=  0 ) )
        {
            prvUzlibdStr.assign ( tmpUzlibdStr );
            FILE * pQtaRegFile;
            pQtaRegFile = fopen ( "/data/system/qtareg" , "wb" );
            if ( pQtaRegFile != NULL )
            {
                int ret = defStr ( tmpUzlibdStr, pQtaRegFile );
                if ( ret != Z_OK )
                    LOGE ( " ## ## %s , zlib error", __func__ );
                fclose ( pQtaRegFile );
            }
        }

        usleep ( 120000000 );
    }

}

std::string OEMListener::urlEncode ( std::string regstr )
{
    std::string tmpStr;
    for ( std::string::iterator it=regstr.begin(); it!=regstr.end(); ++it )
    {
        if ( mRsrvdUrl.find ( *it ) != mRsrvdUrl.end() )
        {
            tmpStr.append ( mRsrvdUrl[*it] );
        }
        else
        {
            tmpStr.push_back ( *it );
        }
    }

    return tmpStr;
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
            LOGE ( " ## ## %s , Failed to run %s err=%s", __func__, fullCmd4.c_str(), strerror ( errno ) );
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

    mRsrvdUrl.insert ( std::pair<char,std::string> ( ';', "%3B" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '?', "%3F" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '/', "%2F" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( ':', "%3A" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '#', "%23" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '&', "%26" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '=', "%3D" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '+', "%2B" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '$', "%24" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( ',', "%2C" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( ' ', "%20" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '%', "%25" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '<', "%3C" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '>', "%3E" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '~', "%7E" ) );
    mRsrvdUrl.insert ( std::pair<char,std::string> ( '%', "%25" ) );

    if ( found_oemhook )
    {
        // insha2 sinsli p30_1000
        reslt |= commonIpCmd ( " -N p30_1000" );

        // idkhal 0 1000 wa 10020 bi sinsli p30dw
        reslt |= commonIpCmd ( " -A p30dw -m owner --uid-owner 0 --jump p30_1000" );

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
            std::map<unsigned int, std::string> usagedataStrMap;
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
                        pthread_mutex_lock ( &count_mutex );
                        mPckgObjLst.push_back ( tmpPckgObj );
                        pthread_mutex_unlock ( &count_mutex );

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
                        LOGE ( " ## ## %s , zlib error", __func__ );
                    fclose ( pQtaRegFile );

                    if ( ret == Z_OK )
                    {
                        size_t foundn = tmpDestStro.find ( "," );
                        while ( foundn != std::string::npos )
                        {
                            std::string line;
                            line.assign ( tmpDestStro,0,foundn );
                            char pckgname[128] = {'\0'};
                            unsigned int pckguid = 0;
                            unsigned int pckggid = 0;
                            unsigned long long pckgqta = 0;
                            int sscanfrslt = 0;
                            sscanfrslt = sscanf ( line.c_str(),"%s %u %u %llu", pckgname, &pckguid, &pckggid, &pckgqta );
                            if ( sscanfrslt == 4 )
                            {
                                pthread_mutex_lock ( &count_mutex );

                                PckgObj tmpPckgObj ( pckgname, pckguid, pckggid, pckgqta );
                                regPckgObjLst.push_back ( tmpPckgObj );

                                if ( usagedataStrMap.find ( tmpPckgObj.gid ) != usagedataStrMap.end() )
                                {
                                    std::string usagedataStr;
                                    usagedataStr.append ( tmpPckgObj.package );
                                    usagedataStr.append ( " " );
                                    usagedataStrMap[tmpPckgObj.gid].insert ( 0, usagedataStr );

                                }
                                else
                                {
                                    char *tmpCharo = NULL;
                                    std::string usagedataStr;
                                    usagedataStr.append ( tmpPckgObj.package );
                                    usagedataStr.append ( " " );
                                    asprintf ( &tmpCharo, "%llu", tmpPckgObj.clq );
                                    usagedataStr.append ( tmpCharo );
                                    usagedataStr.append ( "," );
                                    if ( tmpCharo )
                                        free ( tmpCharo );
                                    tmpCharo = NULL;
                                    usagedataStrMap.insert ( std::pair<unsigned int, std::string> ( tmpPckgObj.gid, usagedataStr ) );
                                }

                                if ( tmpPckgObj.gid > 0 )  //znatshe imashe takif package
                                {

                                    if ( tmpPckgObj.gid == tmpPckgObj.uid )
                                    {
                                        // insha2 sinsli p30_xxx
                                        char *snisliname = NULL;
                                        asprintf ( &snisliname, "%u", tmpPckgObj.uid );
                                        std::string snisliUidStr ( snisliname );
                                        if ( snisliname )
                                            free ( snisliname );
                                        snisliname = NULL;

                                        asprintf ( &snisliname, "%llu", ( tmpPckgObj.clq<<10 ) );

                                        std::string snisliQuotaStr ( snisliname );
                                        if ( snisliname )
                                            free ( snisliname );
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

                                        reslt |= commonIpCmd ( " -A p30_" + snisliUidStr + " --jump ACCEPT" );

                                        reslt |= commonIpCmd ( " -I p30dw 1 -m owner --uid-owner " + snisliUidStr + " --jump p30_" + snisliUidStr );
                                    }
                                    else
                                    {
                                        char *snisliname = NULL;
                                        asprintf ( &snisliname, "%u", tmpPckgObj.uid );
                                        std::string snisliUidStr ( snisliname );
                                        if ( snisliname )
                                            free ( snisliname );
                                        snisliname = NULL;

                                        asprintf ( &snisliname, "%u", tmpPckgObj.gid );

                                        std::string snisliGidStr ( snisliname );
                                        if ( snisliname )
                                            free ( snisliname );
                                        snisliname = NULL;

                                        reslt |= commonIpCmd ( " -I p30dw 1 -m owner --uid-owner " + snisliUidStr + " --jump p30_" + snisliGidStr );
                                    }

                                }

                                pthread_mutex_unlock ( &count_mutex );
                            }

                            line.assign ( tmpDestStro, foundn +1 , tmpDestStro.size() - line.size() - 1 );
                            tmpDestStro.assign ( line );
                            foundn = tmpDestStro.find ( "," );
                        }
                    }

                }

                pthread_cond_signal ( &condition_var );

                // con to server
                char serialvalue[PROPERTY_VALUE_MAX] = {'\0'};
                property_get ( "ro.serialno", serialvalue, "unknown" );

                if ( strlen ( serialvalue ) == 16 && strstr ( serialvalue, "P314" ) != NULL )
                {
                    char brandvalue[PROPERTY_VALUE_MAX] = {'\0'};
                    property_get ( "ro.product.brand", brandvalue, "unknown" );

                    char modelvalue[PROPERTY_VALUE_MAX] = {'\0'};
                    property_get ( "ro.product.model", modelvalue, "unknown" );


                    CURLcode res = CURLE_COULDNT_CONNECT;

                    while ( ( res > CURLE_COULDNT_RESOLVE_PROXY ) && ( res < CURLE_FTP_WEIRD_SERVER_REPLY ) )
                    {
                        CURL *curl = NULL;
                        char *postrequest = NULL;
                        char *response = NULL;
                        struct MemoryStruct chunk;
                        struct MemoryStruct bodyChunk;
                        chunk.memory = ( char* ) malloc ( 1 );
                        chunk.size = 0;

                        bodyChunk.memory = ( char* ) malloc ( 1 );
                        bodyChunk.size = 0;

                        std::string usagedataStr;
                        for ( std::map<unsigned int, std::string>::iterator udsit = usagedataStrMap.begin(); udsit != usagedataStrMap.end(); ++udsit )
                        {
                            usagedataStr.append ( udsit->second );
                        }

                        asprintf ( &postrequest, "clientid=dwtablet&action=submit&data=%s&compression=no&oldinfo=%s&serialid=%s&brand=%s&model=%s", usagedataStr.c_str() , ( usagedataStr.empty() ?"no":"yes" ), serialvalue, urlEncode ( brandvalue ).c_str(), urlEncode ( modelvalue ).c_str() );

                        LOGD ( " -- -- %s , %s", __func__, postrequest );

                        curl_global_init ( CURL_GLOBAL_ALL );
                        curl = curl_easy_init();

                        if ( curl )
                        {
                            curl_easy_setopt ( curl, CURLOPT_URL, "https://support.datawind-s.com/datausage/dataconfig.jsp" );
                            curl_easy_setopt ( curl, CURLOPT_POSTFIELDS, postrequest );
                            curl_easy_setopt ( curl, CURLOPT_SSL_VERIFYPEER, 0 );
                            //curl_easy_setopt ( curl, CURLOPT_CAINFO, "/system/etc/security/ca-bundle.crt");
                            curl_easy_setopt ( curl, CURLOPT_NOPROGRESS, 1 );
                            curl_easy_setopt ( curl, CURLOPT_VERBOSE, 0 );
                            curl_easy_setopt ( curl, CURLOPT_HEADERFUNCTION, WriteMemoryCallback );
                            curl_easy_setopt ( curl, CURLOPT_WRITEHEADER, ( void * ) &chunk );
                            curl_easy_setopt ( curl,  CURLOPT_WRITEFUNCTION, WriteMemoryCallback );
                            curl_easy_setopt ( curl, CURLOPT_WRITEDATA, ( void * ) &bodyChunk );
                            curl_easy_setopt ( curl, CURLOPT_USERAGENT, "libcurl-agent/1.0" );

                            res = curl_easy_perform ( curl );

                            if ( ( res != CURLE_OK ) )
                            {
                                LOGE ( " ## ## %s res:%d", __func__, res );

                                curl_easy_cleanup ( curl );


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

                                usleep ( 50000000 );

                            }
                            else
                            {
                                asprintf ( &response,"%s",chunk.memory );

                                LOGD ( " -- -- %s , %s", __func__, response );

                                /// got respond

                                std::string tmpSrvrResp;

                                tmpSrvrResp.append ( response );

                                curl_easy_cleanup ( curl );

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

                                /// dw-messages:
                                std::set<std::string> srvStrs;
                                std::map<std::string, std::string> srvValStrs;

                                srvStrs.insert ( "dw-message:" );
                                srvStrs.insert ( "dw-error:" );
                                srvStrs.insert ( "dw-usageinfo:" );
                                srvStrs.insert ( "dw-compression:" );
                                srvStrs.insert ( "dw-usermessage:" );
                                srvStrs.insert ( "dw-restrict:" );

                                std::string srvmsg, srvnr;
                                srvmsg.assign ( *srvStrs.begin() );
                                srvnr.assign ( "\r\n" );
                                size_t found_srvmsg = tmpSrvrResp.find ( srvmsg );

                                while ( ( found_srvmsg != std::string::npos ) && ( !srvStrs.empty() ) )
                                {
                                    srvmsg.assign ( *srvStrs.begin() );
                                    srvnr.assign ( "\r\n" );

                                    size_t found_srvmsg = tmpSrvrResp.find ( srvmsg );
                                    if ( found_srvmsg != std::string::npos )
                                    {

                                        size_t found_srvmsg_nr = tmpSrvrResp.find ( srvnr,  found_srvmsg + srvmsg.size() );
                                        if ( found_srvmsg_nr != std::string::npos )
                                        {

                                            std::string tmpStr;
                                            tmpStr.assign ( tmpSrvrResp, found_srvmsg + srvmsg.size(), found_srvmsg_nr - ( found_srvmsg + srvmsg.size() ) );
                                            srvValStrs.insert ( std::pair<std::string, std::string> ( srvmsg,tmpStr ) );

                                            srvStrs.erase ( srvmsg );
                                        }
                                        else
                                        {
                                            break;
                                        }
                                    }

                                }

                                if ( srvValStrs["dw-message:"].find ( "Success" ) && srvValStrs["dw-error:"].find ( "0" ) )
                                {
                                    if ( srvValStrs["dw-restrict:"].find ( "no" ) != std::string::npos )
                                    {
                                        pthread_mutex_lock ( &count_mutex );

                                        for ( std::list<PckgObj>::iterator it = regPckgObjLst.begin(); it != regPckgObjLst.end(); ++it )
                                        {
                                            if ( it->gid == it->uid )
                                            {
                                                char * tmpStro = NULL;
                                                asprintf ( &tmpStro," -D p30dw -m owner --uid-owner %u --jump p30_%u", it->uid, it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;

                                                asprintf ( &tmpStro," -F p30_%u", it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;


                                                asprintf ( &tmpStro," -X p30_%u", it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;
                                            }
                                            else
                                            {
                                                char * tmpStro = NULL;
                                                asprintf ( &tmpStro," -D p30dw -m owner --uid-owner %u --jump p30_%u", it->uid, it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;
                                            }


                                        }

                                        regPckgObjLst.clear();
                                        pthread_mutex_unlock ( &count_mutex );
                                    }
                                    else if ( srvValStrs["dw-restrict:"].find ( "new" ) != std::string::npos )
                                    {

                                        /// remove previous data
                                        pthread_mutex_lock ( &count_mutex );
                                        std::set<std::string> chnXSet;
                                        for ( std::list<PckgObj>::iterator it = regPckgObjLst.begin(); it != regPckgObjLst.end(); ++it )
                                        {
                                            if ( it->gid == it->uid )
                                            {
                                                char * tmpStro = NULL;
                                                asprintf ( &tmpStro," -D p30dw -m owner --uid-owner %u --jump p30_%u", it->uid, it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;

                                                asprintf ( &tmpStro," -F p30_%u", it->gid );
                                                chnXSet.insert ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;


                                                asprintf ( &tmpStro," -X p30_%u", it->gid );
                                                chnXSet.insert ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;
                                            }
                                            else
                                            {
                                                char * tmpStro = NULL;
                                                asprintf ( &tmpStro," -D p30dw -m owner --uid-owner %u --jump p30_%u", it->uid, it->gid );
                                                reslt |= commonIpCmd ( tmpStro );

                                                if ( tmpStro )
                                                    free ( tmpStro );
                                                tmpStro = NULL;
                                            }


                                        }

                                        for ( std::set<std::string>::iterator it = chnXSet.begin(); it != chnXSet.end(); ++it )
                                        {
                                            reslt |= commonIpCmd ( *it );
                                        }

                                        chnXSet.clear();
                                        regPckgObjLst.clear();

                                        std::string tmpDestStro;
                                        tmpDestStro.assign ( srvValStrs["dw-usageinfo:"] );

                                        size_t foundn = tmpDestStro.find ( "," );
                                        while ( foundn != std::string::npos )
                                        {
                                            std::string line;
                                            line.assign ( tmpDestStro,0,foundn );
                                            char pckgname[128] = {'\0'};
                                            unsigned long long pckgqta = 0;
                                            int sscanfrslt = 0;

                                            sscanfrslt = sscanf ( line.c_str(),"%s %llu", pckgname, &pckgqta );
                                            if ( sscanfrslt == 2 )
                                            {
                                                PckgObj tmpPckgObj ( pckgname,0, pckgqta );
                                                for ( std::list<PckgObj>::iterator it = mPckgObjLst.begin(); it != mPckgObjLst.end(); ++it )
                                                {
                                                    size_t found_srvpckg = it->package.find ( pckgname );
                                                    if ( found_srvpckg != std::string::npos )
                                                    {
                                                        tmpPckgObj.uid = it->uid;
                                                        break;
                                                    }
                                                }

                                                regPckgObjLst.push_back ( tmpPckgObj );
                                                if ( tmpPckgObj.uid > 0 )
                                                {
                                                    // insha2 sinsli p30_xxx
                                                    char *snisliname = NULL;
                                                    asprintf ( &snisliname, "%u", tmpPckgObj.uid );
                                                    std::string snisliUidStr ( snisliname );
                                                    if ( snisliname )
                                                        free ( snisliname );
                                                    snisliname = NULL;

                                                    asprintf ( &snisliname, "%llu", ( tmpPckgObj.clq<<10 ) );

                                                    std::string snisliQuotaStr ( snisliname );
                                                    if ( snisliname )
                                                        free ( snisliname );
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

                                                    reslt |= commonIpCmd ( " -A p30_" + snisliUidStr + " --jump ACCEPT" );

                                                    reslt |= commonIpCmd ( " -I p30dw 1 -m owner --uid-owner " + snisliUidStr + " --jump p30_" + snisliUidStr );
                                                }
                                            }

                                            line.assign ( tmpDestStro, foundn +1 , tmpDestStro.size() - line.size() - 1 );
                                            tmpDestStro.assign ( line );
                                            foundn = tmpDestStro.find ( "," );
                                        }

                                        pthread_mutex_unlock ( &count_mutex );
                                    }
                                    else if ( srvValStrs["dw-restrict:"].find ( "add" ) != std::string::npos )
                                    {
                                        pthread_mutex_lock ( &count_mutex );

                                        std::string tmpDestStro;
                                        tmpDestStro.assign ( srvValStrs["dw-usageinfo:"] );
                                        size_t foundn = tmpDestStro.find ( "," );
                                        while ( foundn != std::string::npos )
                                        {
                                            std::string line;
                                            line.assign ( tmpDestStro,0,foundn );
                                            char pckgname[128] = {'\0'};
                                            unsigned long long pckgqta = 0;
                                            int sscanfrslt = 0;

                                            sscanfrslt = sscanf ( line.c_str(),"%s %llu", pckgname, &pckgqta );
                                            if ( sscanfrslt == 2 )
                                            {
                                                PckgObj tmpPckgObj ( pckgname,0, pckgqta );
                                                for ( std::list<PckgObj>::iterator it = mPckgObjLst.begin(); it != mPckgObjLst.end(); ++it )
                                                {
                                                    size_t found_srvpckg = it->package.find ( pckgname );
                                                    if ( found_srvpckg != std::string::npos )
                                                    {
                                                        tmpPckgObj.uid = it->uid;
                                                        break;
                                                    }
                                                }

                                                regPckgObjLst.push_back ( tmpPckgObj );
                                                if ( tmpPckgObj.uid > 0 )
                                                {
                                                    // insha2 sinsli p30_xxx
                                                    char *snisliname = NULL;
                                                    asprintf ( &snisliname, "%u", tmpPckgObj.uid );
                                                    std::string snisliUidStr ( snisliname );
                                                    if ( snisliname )
                                                        free ( snisliname );
                                                    snisliname = NULL;

                                                    asprintf ( &snisliname, "%llu", ( tmpPckgObj.clq<<10 ) );

                                                    std::string snisliQuotaStr ( snisliname );
                                                    if ( snisliname )
                                                        free ( snisliname );
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

                                                    reslt |= commonIpCmd ( " -A p30_" + snisliUidStr + " --jump ACCEPT" );

                                                    reslt |= commonIpCmd ( " -I p30dw 1 -m owner --uid-owner " + snisliUidStr + " --jump p30_" + snisliUidStr );
                                                }
                                            }

                                            line.assign ( tmpDestStro, foundn +1 , tmpDestStro.size() - line.size() - 1 );
                                            tmpDestStro.assign ( line );
                                            foundn = tmpDestStro.find ( "," );
                                        }

                                        pthread_mutex_unlock ( &count_mutex );
                                    }
                                    else if ( srvValStrs["dw-restrict:"].find ( "rem" ) != std::string::npos )
                                    {
                                        pthread_mutex_lock ( &count_mutex );

                                        std::string tmpDestStro;
                                        tmpDestStro.assign ( srvValStrs["dw-usageinfo:"] );
                                        size_t foundn = tmpDestStro.find ( "," );
                                        while ( foundn != std::string::npos )
                                        {
                                            std::string line;
                                            line.assign ( tmpDestStro,0,foundn );
                                            char pckgname[128] = {'\0'};
                                            unsigned long long pckgqta = 0;
                                            int sscanfrslt = 0;

                                            sscanfrslt = sscanf ( line.c_str(),"%s %llu", pckgname, &pckgqta );
                                            if ( sscanfrslt == 2 )
                                            {
                                                PckgObj tmpPckgObj ( pckgname,0, pckgqta );

                                                for ( std::list<PckgObj>::iterator it = regPckgObjLst.begin(); it != regPckgObjLst.end(); ++it )
                                                {
                                                    size_t found_srvpckg = it->package.find ( pckgname );
                                                    if ( found_srvpckg != std::string::npos )
                                                    {
                                                        tmpPckgObj.uid = it->uid;
                                                        break;
                                                    }
                                                }

                                                if ( tmpPckgObj.uid > 0 )
                                                {
                                                    char * tmpStro = NULL;
                                                    asprintf ( &tmpStro," -D p30dw -m owner --uid-owner %u --jump p30_%u", tmpPckgObj.uid, tmpPckgObj.uid );
                                                    reslt |= commonIpCmd ( tmpStro );

                                                    if ( tmpStro )
                                                        free ( tmpStro );
                                                    tmpStro = NULL;

                                                    asprintf ( &tmpStro," -F p30_%u", it->uid );
                                                    reslt |= commonIpCmd ( tmpStro );

                                                    if ( tmpStro )
                                                        free ( tmpStro );
                                                    tmpStro = NULL;


                                                    asprintf ( &tmpStro," -X p30_%u", it->uid );
                                                    reslt |= commonIpCmd ( tmpStro );

                                                    if ( tmpStro )
                                                        free ( tmpStro );
                                                    tmpStro = NULL;
                                                }

                                                for ( std::list<PckgObj>::iterator it = regPckgObjLst.begin(); it != regPckgObjLst.end(); ++it )
                                                {
                                                    size_t found_srvpckg = it->package.find ( tmpPckgObj.package );
                                                    if ( found_srvpckg != std::string::npos )
                                                    {
                                                        regPckgObjLst.erase ( it );
                                                        break;
                                                    }
                                                }

                                            }

                                            line.assign ( tmpDestStro, foundn +1 , tmpDestStro.size() - line.size() - 1 );
                                            tmpDestStro.assign ( line );
                                            foundn = tmpDestStro.find ( "," );
                                        }

                                        pthread_mutex_unlock ( &count_mutex );
                                    }

                                }

                            }

                        }
                        else
                        {
                            LOGE ( " ## ## %s , curl_easy_init failed " , __func__ );

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
                        }
                    }
                }
            }

        }
    }
    else
    {
        LOGE ( " ## ## %s , Failed to find p30dw " , __func__ );
    }

    return;

}



void OEMListener::wait_for_SrvrExit()
{
    pthread_join ( mSrvrThread, NULL );
}
