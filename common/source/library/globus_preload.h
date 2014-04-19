/*
 * Copyright 1999-2014 University of Chicago
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

#ifndef GLOBUS_PRELOAD_H
#define GLOBUS_PRELOAD_H 1

#include "ltdl.h"

#ifndef lt_preloaded_symbols    
#if defined(_WIN32) || defined(__CYGWIN__) || defined(_WIN32_WCE)
/* DATA imports from DLLs on WIN32 con't be const, because runtime
   relocations are performed -- see ld's documentation on pseudo-relocs.  */
# define LT_DLSYM_CONST
#elif defined(__osf__)
   /* This system does not cope well with relocations in const data.  */
# define LT_DLSYM_CONST
#else
# define LT_DLSYM_CONST const
#endif
#define lt_preloaded_symbols    lt__PROGRAM__LTX_preloaded_symbols
/* Ensure C linkage.  */
extern LT_DLSYM_CONST lt_dlsymlist lt__PROGRAM__LTX_preloaded_symbols[];

#ifdef LTDL_SET_PRELOADED_SYMBOLS
#undef LTDL_SET_PRELOADED_SYMBOLS
#endif

#define LTDL_SET_PRELOADED_SYMBOLS() \
        lt_dlpreload_default(lt_preloaded_symbols)
#endif

#endif /* GLOBUS_PRELOAD_H */
