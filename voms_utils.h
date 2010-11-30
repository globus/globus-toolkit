
#ifndef __VOMS_UTILS_H_
#define __VOMS_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <sys/stat.h>
#include <dirent.h>

/*
 * get_vomses()
 *
 * Returns the vomses line for specified path.
 * Returns the pointer to vomses line if succeeded, NULL otherwise.
 */
char **get_vomses(const char *path);

#endif

