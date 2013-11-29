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
#include <pthread.h>
#include <sysutils/FrameworkListener.h>

#include "NetdCommand.h"

class OEMListener {
public:
    OEMListener();
    virtual ~OEMListener() {}
    void SrvrFunction();
    void wait_for_SrvrExit();
private:
    static const char INTERFACE[];
    static const char IPTABLES_PATH[];
    static const char IP6TABLES_PATH[];
    pthread_t mSrvrThread;
};

#endif
