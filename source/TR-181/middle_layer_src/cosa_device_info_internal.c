/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/**************************************************************************

    module: cosa_device_info_internal.c

        For COSA Data Model Library Development

    -------------------------------------------------------------------

    description:

        This file implementes back-end apis for the COSA Data Model Library

        *  CosaDeviceInfoCreate
        *  CosaDeviceInfoInitialize
        *  CosaDeviceInfoRemove
    -------------------------------------------------------------------

    environment:

        platform independent

    -------------------------------------------------------------------

    author:

        COSA XML TOOL CODE GENERATOR 1.0

    -------------------------------------------------------------------

    revision:

        01/11/2011    initial revision.

**************************************************************************/

#include "plugin_main_apis.h"
#include "cosa_device_info_apis.h"
#include "cosa_device_info_dml.h"
#include "cosa_device_info_internal.h"

#if defined (ENABLE_LLD_SUPPORT)
#include "cosa_rbus_handler_apis.h"
#include "cm_agent_webconfig_api.h"
#endif



/**********************************************************************

    caller:     owner of the object

    prototype:

        ANSC_HANDLE
        CosaDeviceInfoCreate
            (
            );

    description:

        This function constructs cosa device info object and return handle.

    argument:  

    return:     newly created device info object.

**********************************************************************/

ANSC_HANDLE
CosaDeviceInfoCreate
    (
        VOID
    )
{
    PCOSA_DATAMODEL_DEVICEINFO   pMyObject    = (PCOSA_DATAMODEL_DEVICEINFO)NULL;

    /*
     * We create object by first allocating memory for holding the variables and member functions.
     */
    pMyObject = (PCOSA_DATAMODEL_DEVICEINFO)AnscAllocateMemory(sizeof(COSA_DATAMODEL_DEVICEINFO));

    if ( !pMyObject )
    {
        return  (ANSC_HANDLE)NULL;
    }


    /*
     * Initialize the common variables and functions for a container object.
     */

    pMyObject->Create            = CosaDeviceInfoCreate;
    pMyObject->Remove            = CosaDeviceInfoRemove;
    pMyObject->Initialize        = CosaDeviceInfoInitialize;

    pMyObject->Initialize   ((ANSC_HANDLE)pMyObject);

    return  (ANSC_HANDLE)pMyObject;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaDeviceInfoInitialize
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa device info object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaDeviceInfoInitialize
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                  returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_DEVICEINFO   pMyObject    = (PCOSA_DATAMODEL_DEVICEINFO)hThisObject;

    /* Initiation all functions */

    /* Initialize middle layer for Device.DeviceInfo.  */
    CosaDmlDIInit(NULL, (PANSC_HANDLE)pMyObject);
   
#if defined (ENABLE_LLD_SUPPORT) 
    cmAgentLldRbusInit();
    webConfigFrameworkInit();
#endif

    return returnStatus;
}

/**********************************************************************

    caller:     self

    prototype:

        ANSC_STATUS
        CosaDeviceInfoRemove
            (
                ANSC_HANDLE                 hThisObject
            );

    description:

        This function initiate  cosa device info object and return handle.

    argument:   ANSC_HANDLE                 hThisObject
            This handle is actually the pointer of this object
            itself.

    return:     operation status.

**********************************************************************/

ANSC_STATUS
CosaDeviceInfoRemove
    (
        ANSC_HANDLE                 hThisObject
    )
{
    ANSC_STATUS                     returnStatus = ANSC_STATUS_SUCCESS;
    PCOSA_DATAMODEL_DEVICEINFO      pMyObject    = (PCOSA_DATAMODEL_DEVICEINFO)hThisObject;

    /* Remove necessary resounce */

    /* Remove self */
    AnscFreeMemory((ANSC_HANDLE)pMyObject);

    return returnStatus;
}


