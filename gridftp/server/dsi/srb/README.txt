Build:
------
1)  First there must be a valid globus installation, and the $GLOBUS_LOCATION 
    environment variable must be set to point to that installation.

2)  ./bootstrap

3)  Run configure.  There is 1 manditory argument:
        --with-srb-path=<path to srb build>
    This needs to point to an SRB client library build.
    (if building with GPT use CONFIGOPTS_GPTMACRO).

4)  Now simply compile the module:

    % make

5)  Finally install it into the GLOBUS_LOCATION.  In order to do this you
    will need write permission for that directory.

    % make install

Running:
--------
To run the GridFTP server with the SRB DSI use the following command:

$GLOBUS_LOCATION/sbin/globus-gridftp-server -p 5000 -dsi srb -auth-level 4

Configuration:
--------------
To set the SRB server with which this DSI will connect set the environment
variable:

GLOBUS_SRB_HOSTNAME=<host>:<port>

Options envs:
    GLOBUS_SRB_DN=<domain name to expect from SRB server>
    GLOBUS_SRB_DEFAULT_RESOURCE=<default srb resource to use>

A configuration file can also be used to set the needed options.  If used 
it is expected to be found at:

$GLOBUS_LOCATION/etc/gridftp_srb.conf

and has the following options:
    srb_hostname            <host>:<port>
    srb_hostname_dn         <domain name to expect from SRB server>
    srb_default_resource    <default srb resource to use>

GRIDMAP
-------
The gridmap file must be sightly different when using the DSI backend.
It has the format:

"<user security DN>" <srb user name>@<domain name>

the environment variable GRIDMAP can be set to direct the server at 
a gridmap file in a non-default location.
