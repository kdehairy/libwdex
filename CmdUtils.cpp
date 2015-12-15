/*
 * Copyright (C) 2008 The Android Open Source Project
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
/*
 * Some utility functions for use with command-line utilities.
 */
#include "DexFile.h"
#include "CmdUtils.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Map the specified DEX file read-only (possibly after expanding it into a
 * temp file from a Jar).  Pass in a MemMapping struct to hold the info.
 * If the file is an unoptimized DEX file, then byte-swapping and structural
 * verification are performed on it before the memory is made read-only.
 *
 * The temp file is deleted after the map succeeds.
 *
 * This is intended for use by tools (e.g. dexdump) that need to get a
 * read-only copy of a DEX file that could be in a number of different states.
 *
 * If "tempFileName" is NULL, a default value is used.  The temp file is
 * deleted after the map succeeds.
 *
 * If "quiet" is set, don't report common errors.
 *
 * Returns 0 (kUTFRSuccess) on success.
 */
UnzipToFileResult dexOpenAndMap(const char* fileName, const char* tempFileName,
    MemMapping* pMap, bool quiet)
{
    UnzipToFileResult result = kUTFRGenericFailure;
    int len = strlen(fileName);
    char tempNameBuf[32];
    bool removeTemp = false;
    int fd = -1;

    if (len < 5) {
        if (!quiet) {
            fprintf(stderr,
                "ERROR: filename must end in .dex\n");
        }
        result = kUTFRBadArgs;
        goto bail;
    }

    result = kUTFRGenericFailure;

    /*
     * Pop open the (presumed) DEX file.
     */
    fd = open(fileName, O_RDONLY | O_BINARY);
    if (fd < 0) {
        if (!quiet) {
            fprintf(stderr, "ERROR: unable to open '%s': %s\n",
                fileName, strerror(errno));
        }
        goto bail;
    }

    if (sysMapFileInShmemWritableReadOnly(fd, pMap) != 0) {
        fprintf(stderr, "ERROR: Unable to map '%s'\n", fileName);
        goto bail;
    }

    /*
     * This call will fail if the file exists on a filesystem that
     * doesn't support mprotect(). If that's the case, then the file
     * will have already been mapped private-writable by the previous
     * call, so we don't need to do anything special if this call
     * returns non-zero.
     */
    sysChangeMapAccess(pMap->addr, pMap->length, true, pMap);

    if (dexSwapAndVerifyIfNecessary((u1*) pMap->addr, pMap->length)) {
        fprintf(stderr, "ERROR: Failed structural verification of '%s'\n",
            fileName);
        goto bail;
    }

    /*
     * Similar to above, this call will fail if the file wasn't ever
     * read-only to begin with. This is innocuous, though it is
     * undesirable from a memory hygiene perspective.
     */
    sysChangeMapAccess(pMap->addr, pMap->length, false, pMap);

    /*
     * Success!  Close the file and return with the start/length in pMap.
     */
    result = kUTFRSuccess;

bail:
    if (fd >= 0)
        close(fd);
    if (removeTemp) {
        /* this will fail if the OS doesn't allow removal of a mapped file */
        if (unlink(tempFileName) != 0) {
            fprintf(stderr, "WARNING: unable to remove temp '%s'\n",
                tempFileName);
        }
    }
    return result;
}
