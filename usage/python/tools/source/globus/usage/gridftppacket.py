# Copyright 1999-2009 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Utilities and objects for processing GridFTP usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket
from globus.usage.dnscache import DNSCache
import time
import re

class GridFTPPacket(CUsagePacket):
    """
    GridFTP Usage Packet handler
    """
    
    __all_init = 0
    # Caches of key -> id maps
    __dns_cache = None
    __gftp_versions = {}
    __gftp_server = {}
    __gftp_users = {}
    __gftp_clients = {}
    __gftp_scheme = {}
    __gftp_dsi = {}
    __gftp_xio_stack = {}
    __gftp_xfer_type = {}
    __gftp_transfer_sizes = {}
    __gftp_block_sizes = {}
    __gftp_buffer_sizes = {}
    __gftp_transfer_rate_sizes = {}
    __db_class = None

    def __init__(self, address, packet):
        CUsagePacket.__init__(self, address, packet)

    
    insert_statement = '''
            INSERT INTO gftp_transfers(
                send_time,
                scheme,
                dsi,
                server_id,
                client_id,
                user_id,
                client_ip,
                remote_data_ip,
                session_id,
                data_channel_stack,
                file_system_stack,
                start_time,
                transfer_time,
                trans_type,
                num_stripes,
                num_streams,
                buffer_size,
                block_size,
                ftp_return_code,
                num_bytes,
                file_name,
                transfer_size_id,
                block_size_id,
                buffer_size_id,
                transfer_rate_size_id)
            VALUES(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

    @staticmethod
    def upload_many(dbclass, cursor, packets):
        """
        Upload many GridFTPPacket usage packets to the database referred to
        by the given cursor. It will also prepare the caches of id tables

        Returns a list of packets that couldn't be inserted
        """
        if GridFTPPacket.__all_init == 0:
            GridFTPPacket.__db_class = dbclass
            GridFTPPacket._all_init = 1
            GridFTPPacket.__init_dns_cache(cursor)
            GridFTPPacket.__init_versions(cursor)
            GridFTPPacket.__init_gftp_server(cursor)
            GridFTPPacket.__init_gftp_users(cursor)
            GridFTPPacket.__init_gftp_clients(cursor)
            GridFTPPacket.__init_gftp_scheme(cursor)
            GridFTPPacket.__init_gftp_dsi(cursor)
            GridFTPPacket.__init_gftp_xio_stack(cursor)
            GridFTPPacket.__init_gftp_xfer_type(cursor)
            GridFTPPacket.__init_gftp_transfer_sizes(cursor)
            GridFTPPacket.__init_gftp_block_sizes(cursor)
            GridFTPPacket.__init_gftp_buffer_sizes(cursor)
            GridFTPPacket.__init_gftp_transfer_rate_sizes(cursor)
            GridFTPPacket.__cursor = cursor
        return CUsagePacket.upload_many(dbclass, cursor, packets)
        
    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A GridFTPPacket object

        Returns:
        Tuple containing
            (send_time, scheme, dsi, server_id, client_id, user_id, client_ip,
             remote_data_ip, session_id, data_channel_stack, file_system_stack,
             start_time, transfer_time, trans_type, num_stripes, num_streams,
             buffer_size, block_size, ftp_return_code, num_bytes, file_name,
             transfer_size_id, block_size_id, buffer_size_id,
             transfer_rate_size_id)
        """

        return (
            dbclass.Timestamp(*self.send_time),
            self.get_scheme_id(GridFTPPacket.__cursor),
            self.get_dsi_id(GridFTPPacket.__cursor),
            self.get_server_id(GridFTPPacket.__cursor),
            self.get_client_id(GridFTPPacket.__cursor),
            self.get_user_id(GridFTPPacket.__cursor),
            self.data.get("CLIENTIP"),
            self.data.get("DATAIP"),
            self.data.get("SESSID"),
            None, # data_channel_stack
            None, # file_system_stack
            GridFTPPacket.timestamp(self.data.get("START")),
            self.interval(self.data.get("START"), self.data.get("END")),
            self.get_xfer_type_id(GridFTPPacket.__cursor),
            self.data.get("STRIPES"),
            self.data.get("STREAMS"),
            self.data.get("BUFFER"),
            self.data.get("BLOCK"),
            self.data.get("CODE"),
            self.data.get("NBYTES"),
            self.data.get("FILE"),
            self.get_transfer_size_id(),
            self.get_block_size_id(),
            self.get_buffer_size_id(),
            self.get_transfer_rate_id())

    def get_host_id(self):
        """
        Determine the host key which matches the HOSTNAME string
        in this packet. If this HOSTNAME is not defined in the cache,
        attempt to insert it into the dns_cache table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this hostname into
        the table

        Returns:
        An integer key to the dns_cache table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        return GridFTPPacket.__dns_cache.get_host_id(\
            self.ip_address, self.data.get("HOSTNAME"))

    def get_scheme_id(self, cursor):
        """
        Determine the scheme_name key which matches the SCHEMA string
        in this packet. If the SCHEMA is not defined in the cache,
        attempt to insert it into the gftp_scheme table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this scheme into
        the table

        Returns:
        An integer key to the gftp_scheme table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        scheme_id = None
        name = self.data.get("SCHEMA")
        if name is not None:
            scheme_id = GridFTPPacket.__gftp_scheme.get(name)
            if scheme_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_scheme_id_seq') AS key
                    """)
                scheme_id = cursor.fetchone()[0]
                values = (scheme_id, name)
                cursor.execute('''
                    INSERT INTO gftp_scheme(id, name)
                    VALUES(%s, %s)
                    ''', values)
                GridFTPPacket.__gftp_scheme[name] = scheme_id
        else:
            scheme_id = None
        return scheme_id

    def get_dsi_id(self, cursor):
        """
        Determine the dsi id key which matches the DSI string
        in this packet. If the dsi is not defined in the cache,
        attempt to insert it into the gftp_dsi table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this DSI into
        the table

        Returns:
        An integer key to the gftp_dsi table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        dsi_id = None
        name = self.data.get('DSI')
        if name is not None:
            dsi_id = GridFTPPacket.__gftp_dsi.get(name)
            if dsi_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_dsi_id_seq') AS key
                    """)
                dsi_id = cursor.fetchone()[0]
                values = (dsi_id, name)
                cursor.execute('''
                    INSERT INTO gftp_dsi(id, name)
                    VALUES(%s, %s)
                    ''', values)
                GridFTPPacket.__gftp_dsi[name] = dsi_id
        return dsi_id

    def get_version_id(self, cursor):
        """
        Determine the version id key which matches the version string
        in this packet. If the version is not defined in the cache,
        attempt to insert it into the gftp_versions table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this version into
        the table

        Returns:
        An integer key to the gftp_versions table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        version_id = None
        version = GridFTPPacket.__parse_version(self.data.get('VER'))

        if version is not None:
            version_id = GridFTPPacket.__gftp_versions.get(version)
            if version_id is None:
                version_list = list(version)
                version_list[3] = GridFTPPacket.__db_class.TimestampFromTicks(
                    version_list[3])

                cursor.execute("""
                    SELECT nextval('gftp_versions_id_seq') AS key
                    """)
                version_id = cursor.fetchone()[0]
                version_list.insert(0, version_id)

                values = tuple(version_list)

                cursor.execute('''
                    INSERT INTO gftp_versions(
                        id,
                        major,
                        minor,
                        flavor,
                        dirt_timestamp,
                        dirt_branch,
                        distro_string)
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ''', values)
                GridFTPPacket.__gftp_versions[version] = version_id
        return version_id

    def get_server_id(self, cursor):
        """
        Determine the server id key which matches the server host id,
        toolkit version, gftp_version, event_modules (EM), and conf_id 
        in this packet. If the server is not defined in the cache,
        attempt to insert it into the gftp_server table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this server into
        the table

        Returns:
        An integer key to the gftp_server table or None if the server is not
        defined in this packet. As a side effect, this
        key may be newly defined and cached.

        """
        server_id = None
        host_id = self.get_host_id()
        gftp_version = self.get_version_id(cursor)
        event_modules = self.data.get('EM')
        conf_id = self.data.get("CONFID")

        if host_id is not None:
            values = (host_id, gftp_version, event_modules, conf_id)
            server_id = GridFTPPacket.__gftp_server.get(values)
            if server_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_server_id_seq') AS key
                    """)
                server_id = cursor.fetchone()[0]
                values_sql = (server_id, host_id, gftp_version, \
                    event_modules, conf_id)
                cursor.execute('''
                    INSERT INTO gftp_server(
                        id,
                        host_id,
                        gftp_version,
                        event_modules,
                        conf_id)
                    VALUES(%s, %s, %s, %s, %s)
                    ''', values_sql)
                GridFTPPacket.__gftp_server[values] = server_id
        return server_id

    def get_client_id(self, cursor):
        """
        Determine the client id key which matches the APP and APPVER attributes
        in this packet. If the APP and APPVER are not defined in the cache,
        attempt to insert them into the gftp_clients table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this client into
        the table

        Returns:
        An integer key to the gftp_clients table or None if the client
        information is not present in this packet. As a side effect, this
        key may be newly defined and cached.

        """
        client_id = None
        appname = self.data.get('APP')
        appver = self.data.get('APPVER')
        if appname is not None and appver is not None:
            values = (appname, appver)
            client_id = GridFTPPacket.__gftp_clients.get(values)
            if client_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_clients_id_seq') AS key
                    """)
                client_id = cursor.fetchone()[0]

                values_sql = (client_id, appname, appver)

                cursor.execute('''
                    INSERT INTO gftp_clients(
                        id, 
                        appname,
                        appver)
                    VALUES(%s, %s, %s)
                    ''', values_sql)
                GridFTPPacket.__gftp_clients[values] = client_id
        return client_id

    def get_user_id(self, cursor):
        """
        Determine the user id key which matches the USER and USERDN attributes
        in this packet. If the NAME and USERDN are not defined in the cache,
        attempt to insert them into the gftp_users table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this user into
        the table

        Returns:
        An integer key to the gftp_users table or None of the user is not
        present in this packet. As a side effect, this key may be newly defined
        and cached.

        """
        user_id = None
        name = self.data.get('USER')
        user_dn = self.data.get('USERDN')
        if name is not None:
            values = (name, user_dn)
            user_id = GridFTPPacket.__gftp_users.get(values)
            if user_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_users_id_seq') AS key
                    """)
                user_id = cursor.fetchone()[0]
                values_sql = (user_id, name, user_dn)
                cursor.execute('''
                    INSERT INTO gftp_users(id, name, dn)
                    VALUES(%s, %s, %s)
                    ''', values_sql)
                GridFTPPacket.__gftp_users[values] = user_id
        return user_id

        
    def get_xfer_type_id(self, cursor):
        """
        Determine the transfer type id key which matches the TYPE attribute
        in this packet. If the TYPE is not defined in the cache, attempt to
        insert it into the gftp_xfer_type table and return that id.

        Arguments:
        self -- A gridftppacket.gridftppacket object
        cursor -- An SQL cursor to use if we need to insert this type into
        the table

        Returns:
        An integer key to the gftp_xfer_type table or None if the type is
        not present. As a side effect, this key may be newly defined and
        cached.

        """
        xfer_type_id = None
        xfer_type = self.data.get('TYPE')
        if xfer_type is not None:
            xfer_type_id = GridFTPPacket.__gftp_xfer_type.get(xfer_type)
            if xfer_type_id is None:
                cursor.execute("""
                    SELECT nextval('gftp_xfer_type_id_seq') AS key
                    """)
                xfer_type_id = cursor.fetchone()[0]

                cursor.execute('''
                    INSERT INTO gftp_xfer_type(id, command)
                    VALUES(%s, %s)
                    ''', (xfer_type_id, xfer_type))
                GridFTPPacket.__gftp_xfer_type[xfer_type] = xfer_type_id
        return xfer_type_id

    @staticmethod
    def get_size_id(value, table):
        """
        Determine which bucket the a value belongs to based on the minimum
        values in a table.

        Arguments:
        value -- The value to look up. Assumed to be a numeric type.
        table -- Cached table of id -> minimum value

        Returns:
        An integer key to the table, or None if the bucket could not be
        determined.

        """
        size_id = None
        old_min = -1
        if value != None:
            int_value = int(value)
            for i in table.keys():
                bucketmin = int(table[i])
                if (int_value >= bucketmin) and (bucketmin >= old_min):
                    old_min = bucketmin
                    size_id = i
        return size_id

    def get_transfer_size_id(self):
        """
        Determine which bucket the transfer size for this packet belongs
        to based on the minimum values in the gftp_transfer_sizes table. 
        The rate is computed from the NBYTES usage packet
        elements. If it is missing, the result is None.

        Arguments:
        self -- A gridftppacket.gridftppacket object

        Returns:
        An integer key to the gftp_transfer_sizes table, or None if
        the bucket could not be determined.

        """
        return GridFTPPacket.get_size_id(
                self.data.get("NBYTES"),
                GridFTPPacket.__gftp_transfer_sizes)

    def get_block_size_id(self):
        """
        Determine which bucket the block size for this packet belongs
        to based on the minimum values in the gftp_block_sizes table. 
        The rate is computed from the BLOCK usage packet
        elements. If it is missing, the result is None.

        Arguments:
        self -- A gridftppacket.gridftppacket object

        Returns:
        An integer key to the gftp_block_sizes table, or None if
        the bucket could not be determined.

        """
        return self.get_size_id(
                self.data.get("BLOCK"),
                GridFTPPacket.__gftp_block_sizes)

    def get_buffer_size_id(self):
        """
        Determine which bucket the buffer size for this packet belongs
        to based on the minimum values in the gftp_buffer_sizes table. 
        The rate is computed from the BUFFER usage packet
        elements. If it is missing, the result is None.

        Arguments:
        self -- A gridftppacket.gridftppacket object

        Returns:
        An integer key to the gftp_buffer_sizes table, or None if
        the bucket could not be determined.

        """
        return self.get_size_id(
                self.data.get("BUFFER"),
                GridFTPPacket.__gftp_buffer_sizes)

    def get_transfer_rate_id(self):
        """
        Determine which bucket the transfer rate for this packet belongs
        to based on the minimum values in the gftp_transfer_rate_sizes table. 
        The rate is computed from the START, END, and NBYTES usage packet
        elements. If any of those are missing, the result is None.

        Arguments:
        self -- A gridftppacket.gridftppacket object

        Returns:
        An integer key to the gftp_transfer_rate_sizes table, or None if
        the rate could not be computed.

        """
        transfer_time = self.interval(
                self.data.get("START"),
                self.data.get("END"))
        transfer_size = self.data.get("NBYTES")
        transfer_rate_id = None
        if transfer_time != None and transfer_size != None:
            # Note: critically depend on the interval being in the form
            # "x.y secs"
            transfer_time_float = float(transfer_time.split(" ")[0])
            transfer_size_float = float(transfer_size)
            if (transfer_time_float > 0) and (transfer_size_float >= 0):
                transfer_rate = transfer_size_float / transfer_time_float
                transfer_rate_id = self.get_size_id(
                        transfer_rate,
                        GridFTPPacket.__gftp_transfer_rate_sizes)
        return transfer_rate_id


    @staticmethod
    def timestamp(datetimestr):
        """
        Convert a string in the form YYYYmmddHHMMSS.S to a SQL driver-specific
        timestamp.

        Arguments:
        datetimestr -- The string to convert

        Return:
        A module-specific SQL timestamp

        """
        if datetimestr == None:
            return None
        [secs_since_epoch, millis] = datetimestr.split('.')
        pyts = time.strptime(secs_since_epoch, '%Y%m%d%H%M%S')
        sqlts = GridFTPPacket.__db_class.Timestamp(
                pyts.tm_year,
                pyts.tm_mon,
                pyts.tm_mday,
                pyts.tm_hour,
                pyts.tm_min,
                float(pyts.tm_sec) + float(millis) / 1000000)
        return sqlts

    @staticmethod
    def timestr_to_float(datetimestr):
        """
        Convert a string in the form YYYYmmddHHMMSS.S to a floating-point
        representation of seconds + fractional seconds since the UNIX epoch

        Arguments:
        self -- A gridftppacket.gridftppacket object
        starttime -- A string representing the timestamp

        Return:
        Floating point representation of the timestamp

        """
        [secs, millis] = datetimestr.split('.')
        pyts = time.strptime(secs, '%Y%m%d%H%M%S')
        secs_since_epoch = time.strftime("%s", pyts)
        return float(secs_since_epoch) + float(millis) / 1000000

    def interval(self, starttime, endtime):
        """
        Compute a time interval between two string time representations in the
        form YYYYmmddHHMMSS.S

        Arguments:
        self -- A gridftppacket.gridftppacket object
        starttime -- A string representing the start of the interval
        endtime -- A string representing the end of the interval

        Return:
        A string containing the difference between the timestamps of the form
        "3.12 seconds" or None if one of starttime or endtime is None.

        """
        if starttime == None or endtime == None:
            return None
        start_float = self.timestr_to_float(starttime)
        end_float = self.timestr_to_float(endtime)
        if start_float > end_float:
            return None
        return "%f secs" % (end_float - start_float)

    @staticmethod
    def __init_dns_cache(cursor):
        """
        Initialize the global DNSCache object which caches the values in
        the similarly-named table.

        Arguments:
        cursor -- An SQL cursor to use to read the dns_cache table

        Returns:
        None, but alters the class-wide variable __dns_cache

        """
        GridFTPPacket.__dns_cache = DNSCache(cursor)

    @staticmethod
    def __init_versions(cursor):
        """
        Initialize the global dictionary gftp_versions which caches the values in
        the similarly-named table.

        The gftp_versions dictionary maps
        (major, minor, flavor, dirt_timestamp, dirt_branch, distro_string) ->
            version_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_versions table

        Returns:
        None, but alters the global variable gftp_versions.

        """
        cursor.execute("""
            SELECT  id,
                    major,
                    minor,
                    flavor,
                    dirt_timestamp,
                    dirt_branch,
                    distro_string
            FROM gftp_versions""")
        for row in cursor:
            [version_id, major, minor, flavor, dirt_timestamp, dirt_branch, \
                distro_string] = row
            dirt_timestamp = int(
                time.strftime("%s", dirt_timestamp.timetuple()))
            GridFTPPacket.__gftp_versions[
                (major, minor, flavor, dirt_timestamp, \
                dirt_branch, distro_string)] = version_id

    @staticmethod
    def __init_gftp_server(cursor):
        """
        Initialize the global dictionary gftp_server which caches the values in
        the similarly-named table. That dictionary maps
        (host_id, gftp_version, conf_id) -> server_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_server table

        Returns:
        None, but alters the global variable gftp_server.

        """
        cursor.execute("""
            SELECT  id,
                    host_id,
                    gftp_version,
                    event_modules,
                    conf_id
            FROM gftp_server""")
        for row in cursor:
            [server_id, host_id, gftp_version, event_modules, conf_id] = row
            GridFTPPacket.__gftp_server[
                (host_id, gftp_version, event_modules, conf_id)] = server_id

    @staticmethod
    def __init_gftp_users(cursor):
        """
        Initialize the global dictionary gftp_users which caches the values in
        the similarly-named table.

        The gftp_users dictionary maps
        (name, dn) -> user_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_users table

        Returns:
        None, but alters the global variable gftp_users.

        """
        cursor.execute("SELECT id, name, dn FROM gftp_users")
        for row in cursor:
            [user_id, user_name, user_dn] = row
            GridFTPPacket.__gftp_users[(user_name, user_dn)] = user_id

    @staticmethod
    def __init_gftp_clients(cursor):
        """
        Initialize the global dictionary gftp_clients which caches the values in
        the similarly-named table.

        The gftp_clients dictionary maps
        (appname, appver) -> client_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_clients table

        Returns:
        None, but alters the global variable gftp_clients.

        """
        cursor.execute("SELECT id, appname, appver FROM gftp_clients")
        for row in cursor:
            [client_id, appname, appver] = row
            GridFTPPacket.__gftp_clients[(appname, appver)] = client_id

    @staticmethod
    def __init_gftp_scheme(cursor):
        """
        Initialize the global dictionary gftp_scheme which caches the values in
        the similarly-named table.

        The gftp_scheme dictionary maps
        name -> scheme_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_scheme table

        Returns:
        None, but alters the global variable gftp_scheme.

        """
        cursor.execute("SELECT id, name FROM gftp_scheme")
        for row in cursor:
            [scheme_id, name] = row
            GridFTPPacket.__gftp_scheme[name] = scheme_id

    @staticmethod
    def __init_gftp_dsi(cursor):
        """
        Initialize the global dictionary gftp_dsi which caches the values in
        the similarly-named table.

        The gftp_dsi dictionary maps
        name -> dsi_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_dsi table

        Returns:
        None, but alters the global variable gftp_dsi.

        """
        cursor.execute("SELECT id, name FROM gftp_dsi")
        for row in cursor:
            [dsi_id, name] = row
            GridFTPPacket.__gftp_dsi[name] = dsi_id

    @staticmethod
    def __init_gftp_xio_stack(cursor):
        """
        Initialize the global dictionary gftp_xio_stack which caches the values in
        the similarly-named table.

        The gftp_xio_stack dictionary maps
        name -> xio_stack_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_xio_stack table

        Returns:
        None, but alters the global variable gftp_xio_stack.

        """
        cursor.execute("SELECT id, name FROM gftp_xio_stack")
        for row in cursor:
            [stack_id, name] = row
            GridFTPPacket.__gftp_xio_stack[name] = stack_id

    @staticmethod
    def __init_gftp_xfer_type(cursor):
        """
        Initialize the global dictionary gftp_xfer_type which caches the values in
        the similarly-named table.

        The gftp_xfer_type dictionary maps
        command -> xfer_type_id

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_xfer_type table

        Returns:
        None, but alters the global variable gftp_xfer_type.

        """
        cursor.execute("SELECT id, command FROM gftp_xfer_type")
        for row in cursor:
            [xfer_type_id, command] = row
            GridFTPPacket.__gftp_xfer_type[command] = xfer_type_id

    @staticmethod
    def __init_gftp_transfer_sizes(cursor):
        """
        Initialize the global dictionary gftp_transfer_sizes which caches the
        values in the similarly-named table.

        The gftp_transfer_sizes dictionary maps
        id -> minimum_size

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_transfer_sizes table

        Returns:
        None, but alters the global variable gftp_transfer_sizes.

        """
        cursor.execute("SELECT id, minimum_size FROM gftp_transfer_sizes")
        for row in cursor:
            [transfer_size_id, minimum_size] = row
            GridFTPPacket.__gftp_transfer_sizes[transfer_size_id] = minimum_size

    @staticmethod
    def __init_gftp_block_sizes(cursor):
        """
        Initialize the global dictionary gftp_block_sizes which caches the
        values in the similarly-named table.

        The gftp_block_sizes dictionary maps
        id -> minimum_size

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_block_sizes table

        Returns:
        None, but alters the global variable gftp_block_sizes.

        """
        cursor.execute("SELECT id, minimum_size FROM gftp_block_sizes")
        for row in cursor:
            [block_size_id, minimum_size] = row
            GridFTPPacket.__gftp_block_sizes[block_size_id] = minimum_size

    @staticmethod
    def __init_gftp_buffer_sizes(cursor):
        """
        Initialize the global dictionary gftp_buffer_sizes which caches the
        values in the similarly-named table.

        The gftp_buffer_sizes dictionary maps
        id -> minimum_size

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_buffer_sizes table

        Returns:
        None, but alters the global variable gftp_buffer_sizes.

        """
        cursor.execute("SELECT id, minimum_size FROM gftp_buffer_sizes")
        for row in cursor:
            [buffer_size_id, minimum_size] = row
            GridFTPPacket.__gftp_buffer_sizes[buffer_size_id] = minimum_size
        
    @staticmethod
    def __init_gftp_transfer_rate_sizes(cursor):
        """
        Initialize the global dictionary gftp_transfer_rate_sizes which caches the
        values in the similarly-named table.

        The gftp_transfer_rate_sizes dictionary maps
        id -> minimum_size

        Arguments:
        cursor -- An SQL cursor to use to read the gftp_transfer_rate_sizes table

        Returns:
        None, but alters the global variable gftp_transfer_rate_sizes.

        """
        cursor.execute("SELECT id, minimum_size FROM gftp_transfer_rate_sizes")
        for row in cursor:
            [transfer_rate_id, minimum_size] = row
            GridFTPPacket.__gftp_transfer_rate_sizes[transfer_rate_id] = \
                minimum_size

    # Regular expression to handle GridFTP Server version strings such as
    # 2.1 (gcc32dbg, 1122653280-63)
    # 3.14 (gcc32dbg, 1222134484-78) [Globus Toolkit 4.2.0]
    version_re = re.compile(\
        "([0-9]+)\\.([0-9]+) \\(([^,]*), " + \
        "([0-9]+)-([0-9]+)\\)( \\[([^\\]]*)\\])?")

    @staticmethod
    def __parse_version(verstring):
        """
        Parse a gridftp version string of the form
        major.minor (flavor, dirttimestamp-dirtbranch) [distrostring]

        Arguments:
        verstring -- The string to parse

        Returns:
        A tuple containing (in order):
            major, minor, flavor, dirt_timestamp, dirt_branch, distro_string
        parsed from the verstring parameter.

        """
        if verstring == None:
            return None

        matches = GridFTPPacket.version_re.match(verstring)
        if matches != None:
            return (
                int(matches.group(1)),
                int(matches.group(2)),
                matches.group(3),
                int(matches.group(4)),
                int(matches.group(5)),
                matches.group(7))
        else:
            return None

# vim: ts=4:sw=4:syntax=python
