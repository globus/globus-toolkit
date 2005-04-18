/*
 * Portions of this file Copyright 1999-2005 University of Chicago
 * Portions of this file Copyright 1999-2005 The University of Southern California.
 *
 * This file or a portion of this file is licensed under the
 * terms of the Globus Toolkit Public License, found at
 * http://www.globus.org/toolkit/download/license.html.
 * If you redistribute this file, with or without
 * modifications, you must include this notice in the file.
 */

#include "globus_gram_client.h"

int main(int argc, char *argv[])
{
    globus_module_activate(GLOBUS_GRAM_CLIENT_MODULE);
    globus_module_deactivate(GLOBUS_GRAM_CLIENT_MODULE);

    return 0;
}
