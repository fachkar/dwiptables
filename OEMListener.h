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

#ifndef _OEMLISTENER_H__
#define _OEMLISTENER_H__

#include <string>
#include <list>
#include <pthread.h>
#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"

class PckgObj
{
public:
    PckgObj ( std::string pckgname = "", unsigned int puid = 0, unsigned long long qta = 0 , unsigned short statuso = 0) :package ( pckgname ),uid ( puid ),clq ( qta ), status(statuso) {}
    ~PckgObj(){}
    PckgObj ( const PckgObj& cctor ) :package ( cctor.package ),uid ( cctor.uid ),clq ( cctor.clq ), status(cctor.status) {}
    PckgObj& operator= ( const PckgObj& assign_opt )
    {
        if ( this == &assign_opt )
            return *this;
        package = assign_opt.package;
        uid = assign_opt.uid;
        clq = assign_opt.clq;
        status = assign_opt.status;
        return *this;
    }

    std::string package;
    unsigned int uid;
    unsigned long long clq;
    unsigned short status;
};


class OEMListener
{
public:
    OEMListener();
    virtual ~OEMListener() {mPckgObjLst.clear();}
    void SrvrFunction();
    void wait_for_SrvrExit();
    int commonIpCmd ( std:: string cmd );
    int infStr(FILE *source, std::string& rtrnStr);
    std::string DeflateString ( const std::string& str );
private:
    static const char INTERFACE[];
    static const char IPTABLES_PATH[];
    static const char IP6TABLES_PATH[];
    pthread_t mSrvrThread;
    std::list<PckgObj> mPckgObjLst;
};

#endif
