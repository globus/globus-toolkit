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


GlobusXIODeclareModule(file); GlobusXIODeclareModule(gsi); GlobusXIODeclareModule(http); GlobusXIODeclareModule(mode_e); GlobusXIODeclareModule(ordering); GlobusXIODeclareModule(queue); GlobusXIODeclareModule(tcp); GlobusXIODeclareModule(telnet); GlobusXIODeclareModule(udp); GlobusXIODeclareModule(udt); 

static globus_extension_builtin_t       local_extensions[] = 
{
     {GlobusXIOExtensionName(file), GlobusXIOMyModule(file)}, {GlobusXIOExtensionName(gsi), GlobusXIOMyModule(gsi)}, {GlobusXIOExtensionName(http), GlobusXIOMyModule(http)}, {GlobusXIOExtensionName(mode_e), GlobusXIOMyModule(mode_e)}, {GlobusXIOExtensionName(ordering), GlobusXIOMyModule(ordering)}, {GlobusXIOExtensionName(queue), GlobusXIOMyModule(queue)}, {GlobusXIOExtensionName(tcp), GlobusXIOMyModule(tcp)}, {GlobusXIOExtensionName(telnet), GlobusXIOMyModule(telnet)}, {GlobusXIOExtensionName(udp), GlobusXIOMyModule(udp)}, {GlobusXIOExtensionName(udt), GlobusXIOMyModule(udt)}, {NULL, NULL}
};
