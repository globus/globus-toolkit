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
Utilities and objects for processing GRAM5 usage packets.
"""

from globus.usage.cusagepacket import CUsagePacket
from globus.usage.dnscache import DNSCache
import time
import re

class GRAM5Packet(CUsagePacket):
    """
    GRAM5 Usage Packet handler
    """
    
    __all_init = 0
    # Caches of key -> id maps
    dns_cache = None
    __lrms = dict()
    __job_managers = dict()
    __job_manager_instances_by_uuid = dict()
    clients = dict()
    executables = dict()
    __versions = dict()
    __rsl_attributes = dict()
    __rsl_bitfields = dict()
    job_type_ids = dict()
    db_class = None

    def __init__(self, address, packet):
        CUsagePacket.__init__(self, address, packet)

    
    @staticmethod
    def pre_upload(dbclass, cursor):
        if GRAM5Packet.__all_init == 0:
            GRAM5Packet.db_class = dbclass

            GRAM5Packet._all_init = 1
            GRAM5Packet.__init_dns_cache(cursor)
            GRAM5Packet.__init_versions(cursor)
            GRAM5Packet.__init_lrms(cursor)
            GRAM5Packet.__init_job_managers(cursor)
            #GRAM5Packet.__init_job_manager_instances(cursor)
            GRAM5Packet.__init_rsl_attributes(cursor)
            GRAM5Packet.__init_rsl_bitfields(cursor)
            GRAM5Packet.__init_job_type_ids(cursor)
            GRAM5Packet.__init_clients(cursor)
            GRAM5Packet.__init_executables(cursor)
            GRAM5Packet.cursor = cursor

    @staticmethod
    def upload_many(dbclass, cursor, packets):
        """
        Upload many GRAM5Packet usage packets to the database referred to
        by the given cursor. It will also prepare the caches of id tables.

        Returns an array of bad packets
        """
        GRAM5Packet.pre_upload(dbclass, cursor)
        return CUsagePacket.upload_many(dbclass, cursor, packets)

    def get_job_manager_id(self, cursor):
        """
        Determine the job manager key which matches the host, version,
        LRM, and configuration in this packet. If this job manager instance
        is not defined in the table, attempt to insert it into the
        gram5_job_managers table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this job manager
        into the table

        Returns:
        An integer key to the gram5_job_managers table or None if the job
        manager is not defined or it can't be parsed. As a side effect, this
        key may be newly defined and cached.
        """
        host_id = self.get_host_id()
        version_id = self.get_version_id(cursor)
        lrm_id = self.get_lrm_id(cursor)
        seg_used = (self.data.get('F') == '0')
        poll_used = (self.data.get('F') == '1')
        audit_used = (self.data.get('G') == '1')

        values = (host_id, version_id, lrm_id, seg_used, poll_used, audit_used)
        job_manager_id = GRAM5Packet.__job_managers.get(values)

        if job_manager_id is None:
            cursor.execute("select nextval('gram5_job_managers_id_seq') as key")
            job_manager_id = cursor.fetchone()[0]
            values_sql = (job_manager_id, host_id, version_id, \
                lrm_id, seg_used, poll_used, audit_used)

            cursor.execute('''
                INSERT INTO gram5_job_managers(
                    id,
                    host_id,
                    version,
                    lrm_id,
                    seg_used,
                    poll_used,
                    audit_used)
                VALUES(%s, %s, %s, %s, %s, %s, %s)
                ''', values_sql)
            GRAM5Packet.__job_managers[values] = job_manager_id
        return job_manager_id

    def get_job_manager_instance_id(self, cursor):
        """
        Determine the job manager instance key which matches the job manager
        start time, host and configuration in this packet. If this job manager
        instance is not defined in the table, attempt to insert it into the
        gram5_job_manager_instances table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this job manager
        instance into the table

        Returns:
        An integer key to the gram5_job_managers table or None if the job
        manager is not defined or it can't be parsed. As a side effect, this
        key may be newly defined and cached.
        """
        job_manager_id = self.get_job_manager_id(cursor)
        uuid = self.data.get('B')
        start_time = GRAM5Packet.TimestampFromTicks(
                float(self.data.get('A')))
        byuuidresult = GRAM5Packet.__job_manager_instances_by_uuid.get(uuid)
        job_manager_instance_id = None

        if byuuidresult is None:
            # Not in cache -- check to see if it's in the table
            cursor.execute("""
                SELECT id, job_manager_id
                FROM gram5_job_manager_instances
                WHERE uuid = '%s'""" % (uuid) )
            for row in cursor:
                [jmi_id, job_manager_id] = row
                GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                    (jmi_id, job_manager_id)
                byuuidresult = (jmi_id, job_manager_id)
                break

        if byuuidresult is not None:
            (job_manager_instance_id, jmid) = byuuidresult
        if job_manager_instance_id is None:
            cursor.execute( \
                "select nextval('gram5_job_manager_instances_id_seq') as key")
            job_manager_instance_id = cursor.fetchone()[0]
            values = (job_manager_instance_id, job_manager_id, uuid, start_time)
            cursor.execute('''
                INSERT INTO gram5_job_manager_instances(
                        id,
                        job_manager_id,
                        uuid,
                        start_time)
                VALUES(%s, %s, %s, %s)''', values)
            GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                    (job_manager_instance_id, job_manager_id)
        elif jmid is None:
            values = (job_manager_id, start_time, uuid)
            cursor.execute('''
                UPDATE gram5_job_manager_instances
                SET job_manager_id=%s, start_time=%s
                WHERE uuid=%s
                ''', values)
            GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                    (job_manager_instance_id, job_manager_id)
        return job_manager_instance_id

    def get_job_manager_instance_id_by_uuid(self, cursor):
        """
        Determine the job manager instance key which matches the job manager
        UUID and start time. If this instance is not defined in the table,
        attempt to insert it into the
        gram5_job_manager_instances table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this job manager
        instance into the table

        Returns:
        An integer key to the gram5_job_manager_instances table or None if the
        job manager is not defined or it can't be parsed. As a side effect,
        this key may be newly defined and cached.
        """
        uuid = self.data.get('B')
        start_time = None
        if self.data.get('A') != None:
            start_time = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get('A')))
        job_manager_instance_id = None
        by_uuid_entry = GRAM5Packet.__job_manager_instances_by_uuid.get(uuid)
        if by_uuid_entry is None:
            # Not in cache -- check to see if it's in the table
            cursor.execute("""
                SELECT id, job_manager_id
                FROM gram5_job_manager_instances
                WHERE uuid = '%s'""" % (uuid) )
            for row in cursor:
                [jmi_id, job_manager_id] = row
                GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                    (jmi_id, job_manager_id)
                by_uuid_entry = (jmi_id, job_manager_id)
                break
        if by_uuid_entry is not None:
            job_manager_instance_id = by_uuid_entry[0]
        if job_manager_instance_id is None:
            cursor.execute("""
                select nextval('gram5_job_manager_instances_id_seq') as key
                """)
            job_manager_instance_id = cursor.fetchone()[0]
            values = (job_manager_instance_id, uuid, start_time)

            cursor.execute('''
                INSERT INTO gram5_job_manager_instances(
                        id,
                        uuid,
                        start_time)
                VALUES(%s, %s, %s)
                ''', values)
            GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                    (job_manager_instance_id, None)
        return job_manager_instance_id

    def get_host_id(self):
        """
        Determine the host key which matches the HOSTNAME string
        in this packet. If this HOSTNAME is not defined in the cache,
        attempt to insert it into the dns_cache table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this hostname into
        the table

        Returns:
        An integer key to the dns_cache table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        return GRAM5Packet.dns_cache.get_host_id(
                self.ip_address,
                self.data.get("HOSTNAME"))

    def get_lrm_id(self, cursor):
        """
        Determine the LRM key which matches the LRM 
        in this packet. If this LRM is not defined in the cache,
        attempt to insert it into the gram5_lrms table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this hostname into
        the table

        Returns:
        An integer key to the dns_cache table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        lrm_id = None
        lrm = self.data.get("E")

        if lrm is not None:
            if lrm == 'jobmanager-condor':
                lrm = 'condor'
            lrm_id = GRAM5Packet.__lrms.get(lrm)
            if lrm_id is None:
                cursor.execute("""
                    SELECT nextval('gram5_lrms_id_seq') as key
                    """)
                lrm_id = cursor.fetchone()[0]

                values = (lrm_id, lrm)
                cursor.execute('''
                    INSERT INTO gram5_lrms(id, lrm) VALUES(%s, %s)
                    ''', values)
                GRAM5Packet.__lrms[lrm] = lrm_id
        return lrm_id

    def get_version_id(self, cursor):
        """
        Determine the version id key which matches the version string
        in this packet. If the version is not defined in the cache,
        attempt to insert it into the gram5_versions table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this version into
        the table

        Returns:
        An integer key to the gram5_versions table or None if the version is
        not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.

        """
        version_id = None
        version = self.__parse_version()

        if version is not None:
            version_id = GRAM5Packet.__versions.get(version)
            if version_id is None:
                cursor.execute("""
                    select nextval('gram5_versions_id_seq') as key
                    """)
                version_id = cursor.fetchone()[0]
                version_list = list(version)
                version_list[3] = GRAM5Packet.TimestampFromTicks(
                    version_list[3])
                version_list.insert(0, version_id)
                values_sql = tuple(version_list)

                cursor.execute('''
                    INSERT INTO gram5_versions(
                        id,
                        major,
                        minor,
                        flavor,
                        dirt_timestamp,
                        dirt_branch,
                        distro_string)
                    VALUES(%s, %s, %s, %s, %s, %s, %s)
                    ''', values_sql)
                GRAM5Packet.__versions[version] = version_id
        return version_id

    @staticmethod
    def __init_dns_cache(cursor):
        """
        Initialize the global DNSCache object which caches the values in
        the similarly-named table.

        Arguments:
        cursor -- An SQL cursor to use to read the dns_cache table

        Returns:
        None, but alters the class-wide variable dns_cache

        """
        GRAM5Packet.dns_cache = DNSCache(cursor)

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
            FROM gram5_versions""")
        for row in cursor:
            [version_id, major, minor, flavor, dirt_timestamp, dirt_branch, \
                distro_string] = row
            dirt_timestamp = int(
                time.strftime("%s", dirt_timestamp.timetuple()))
            GRAM5Packet.__versions[
                (major, minor, flavor, dirt_timestamp, \
                dirt_branch, distro_string)] = version_id

    # Regular expression to handle GRAM5 Server version strings such as
    # 3.14 (gcc32dbg, 1222134484-78) [Globus Toolkit 4.2.0]
    version_re = re.compile(\
        "([0-9]+)\\.([0-9]+) \\(([^,]*), " + \
        "([0-9]+)-([0-9]+)\\)( \\[([^\\]]*)\\])?")

    def __parse_version(self):
        """
        Parse a gram version string of the form
        major.minor (flavor, dirttimestamp-dirtbranch) [distrostring]

        Arguments:
        verstring -- The string to parse

        Returns:
        A tuple containing (in order):
            major, minor, flavor, dirt_timestamp, dirt_branch, distro_string
        parsed from the verstring parameter.

        """
        verstring = self.data.get("D")
        if verstring == None:
            return None

        matches = GRAM5Packet.version_re.match(verstring)
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

    @staticmethod
    def __init_lrms(cursor):
        """
        Initialize the dictionary GRAM5Packet.__lrms which caches the values in
        the gram5_lrms table.

        The dictionary maps
        lrm -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_lrms table

        Returns:
        None, but alters the global variable GRAM5Packet.__lrms.

        """
        cursor.execute("""
            SELECT id, lrm
            FROM gram5_lrms""")
        for row in cursor:
            [lrm_id, lrm] = row
            GRAM5Packet.__lrms[lrm] = lrm_id

    @staticmethod
    def __init_job_managers(cursor):
        """
        Initialize the dictionary GRAM5Packet.__job_managers which caches the
        values in the gram5_job_managers table.

        The dictionary maps
        (host_id, version, lrm_id, seg_used, poll_used, audit_used) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_job_managers table

        Returns:
        None, but alters the global variable GRAM5Packet.__job_managers.

        """

        cursor.execute("""
            SELECT id, host_id, version, lrm_id,
                    seg_used, poll_used, audit_used
            FROM gram5_job_managers""")
        for row in cursor:
            [jm_id, host_id, version, lrm_id, seg_used, poll_used, audit_used] \
                    = row
            values = (host_id, version, lrm_id, seg_used, poll_used, audit_used)
            GRAM5Packet.__job_managers[values] = jm_id

    @staticmethod
    def __init_job_manager_instances(cursor):
        """
        Initialize the dictionary GRAM5Packet.__job_manager_instances_by_uuid
        which caches the values in the gram5_job_manager_instances table.

        The dictionary maps
        (job_manager_id, uuid, start_time) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_job_manager_instances
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.__job_manager_instances_by_uuid.

        """

        cursor.execute("""
            SELECT id, job_manager_id, uuid, start_time
            FROM gram5_job_manager_instances""")
        for row in cursor:
            [jmi_id, job_manager_id, uuid, start_time] = row
            GRAM5Packet.__job_manager_instances_by_uuid[uuid] = \
                (jmi_id, job_manager_id)

    @staticmethod
    def __init_rsl_attributes(cursor):
        """
        Initialize the dictionary GRAM5Packet.__rsl_attributes which
        caches the values in the gram5_rsl_attributes table.

        The dictionary maps
        (attribute_name) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_rsl_attributes
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.__rsl_attributes.

        """

        cursor.execute("""
            SELECT id, attribute
            FROM gram5_rsl_attributes""")
        for row in cursor:
            [rsl_id, attribute] = row
            GRAM5Packet.__rsl_attributes[attribute] = rsl_id

    @staticmethod
    def __init_rsl_bitfields(cursor):
        """
        Initialize the dictionary GRAM5Packet.__rsl_bitfields which
        caches the values in the gram5_rsl_bitfields table.

        The dictionary maps
        (bitfield) -> bitfield

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_rsl_attributes
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.__rsl_bitfields.

        """

        cursor.execute("""
            SELECT bitfield
            FROM gram5_rsl_attribute_groups""")
        for row in cursor:
            [bitfield] = row
            GRAM5Packet.__rsl_bitfields[bitfield] = bitfield

    @staticmethod
    def __init_job_type_ids(cursor):
        """
        Initialize the dictionary GRAM5Packet.job_type_ids which
        caches the values in the gram5_job_types table.

        The dictionary maps
        (jobtype) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_job_types
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.job_type_ids.

        """

        cursor.execute("""
            SELECT id, jobtype
            FROM gram5_job_types""")
        for row in cursor:
            [jobtypeid, jobtype] = row
            GRAM5Packet.job_type_ids[jobtype] = jobtypeid

    @staticmethod
    def __init_clients(cursor):
        """
        Initialize the dictionary GRAM5Packet.clients which
        caches the values in the gram5_client table.

        The dictionary maps
        (host_id, dn) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_client
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.clients.

        """

        cursor.execute("""
            SELECT id, host_id, dn
            FROM gram5_client""")
        for row in cursor:
            [clientid, host_id, clientdn] = row
            values = (host_id, clientdn)
            GRAM5Packet.clients[values] = clientid

    @staticmethod
    def __init_executables(cursor):
        """
        Initialize the dictionary GRAM5Packet.executables which
        caches the values in the gram5_executable table.

        The dictionary maps
        (host_id, dn) -> id

        Arguments:
        cursor -- An SQL cursor to use to read the gram5_executable
        table

        Returns:
        None, but alters the global variable
        GRAM5Packet.executables.

        """

        cursor.execute("""
            SELECT id, executable, arguments
            FROM gram5_executable""")
        for row in cursor:
            [exeid, executable, arguments] = row
            values = (exeid, executable, arguments)
            GRAM5Packet.executables[values] = exeid

    def get_lifetime(self):
        """
        Compute the lifetime of the job manager instance as the delta between
        the job manager start time and the packet send time.

        Arguments:
        self -- The packet containing timestamp data

        Returns:
        A string of the form "X seconds" containing the difference between
        those times as floats.
        """
        start_time = float(self.data.get('A'))
        send_time = self.send_time_ticks
        return "%f seconds" % (send_time - start_time)

    @staticmethod
    def get_rsl_attribute_index(attr, cursor):
        attribute_id = GRAM5Packet.__rsl_attributes.get(attr)
        if attribute_id is None:
            cursor.execute("""
                SELECT nextval('gram5_rsl_attributes_id_seq') as key
                """)
            attribute_id = cursor.fetchone()[0]
            values = (attribute_id, attr, True)
            cursor.execute(
                '''INSERT INTO gram5_rsl_attributes(
                        id,
                        attribute,
                        extension)
                    VALUES(%s, %s, %s)
                    ''', values)
            GRAM5Packet.__rsl_attributes[attr] = attribute_id
        return attribute_id

    def get_rsl_bitfield(self, cursor):
        # Job Manager sends standard attributes in a bitfield
        bitfield = int(self.data.get('1'))

        # Add bits to the bitfield for extension attributes
        attrs = self.data.get('4')
        if attrs is not None and attrs != '':
            extra_rsl = attrs.split(',')
            for attr in extra_rsl:
                attr_index = GRAM5Packet.get_rsl_attribute_index(attr, cursor)
                bitfield = bitfield | (2**attr_index)

        attribute_list = []

        for (name, rslid) in GRAM5Packet.__rsl_attributes.items():
            if (bitfield & (2**int(rslid))) != 0:
                attribute_list.append(name)
        attribute_list.sort()

        if GRAM5Packet.__rsl_bitfields.get(bitfield) is None:
            cursor.execute('''
                    INSERT INTO gram5_rsl_attribute_groups(
                            bitfield,
                            attributes)
                    VALUES(%s, %s)''', (bitfield, ','.join(attribute_list)[0:512]))
            GRAM5Packet.__rsl_bitfields[bitfield] = bitfield
            for (name, rslid) in GRAM5Packet.__rsl_attributes.items():
                if (bitfield & (2**int(rslid))) != 0:
                    cursor.execute('''
                        INSERT INTO gram5_rsl_attribute_group_membership(
                                bitfield,
                                member_attribute)
                        VALUES(%s, %s)''', (bitfield, int(rslid)))

        return bitfield

    def get_executable_id(self, cursor):
        executable_id = None
        executable = self.data.get('6')
        arguments = self.data.get('7')

        values = (executable, arguments)

        if executable is not None:
            executable_id = GRAM5Packet.executables.get(values)
            if executable_id is None:
                cursor.execute("""
                    SELECT nextval('gram5_executable_id_seq') as key
                    """)
                executable_id = cursor.fetchone()[0]
                values_sql = (executable_id, executable, arguments)

                cursor.execute('''
                        INSERT INTO gram5_executable(
                            id,
                            executable,
                            arguments)
                        VALUES(%s,%s, %s)
                        ''', values_sql)
                GRAM5Packet.executables[values] = executable_id
        return executable_id

    @staticmethod
    def TimestampFromTicks(ticks):
        timestamp = 0
        try: 
            timestamp = GRAM5Packet.db_class.TimestampFromTicks(float(ticks))
        except:
            timestamp = GRAM5Packet.db_class.TimestampFromTicks(
                round(float(ticks),0))
        return timestamp

class GRAM5JMPacket(GRAM5Packet):
    """
    GRAM5 Usage Packet handler for job manager status packets
    """
    __seen_packets__ = {}
    
    def __init__(self, address, packet):
        GRAM5Packet.__init__(self, address, packet)

    
    insert_statement = '''
            INSERT INTO gram5_job_manager_status(
                job_manager_instance_id,
                restarted_jobs,
                status_time,
                lifetime,
                total_jobs,
                total_failed,
                total_canceled,
                total_done,
                total_dry_run,
                peak_jobs,
                current_jobs,
                unsubmitted,
                stage_in,
                pending,
                active,
                stage_out,
                failed,
                done)
            VALUES(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s)'''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A GRAM5JMPacket object

        Returns:
        Tuple containing
            (job_manager_instance_id, restarted_jobs,
             status_time, lifetime, total_jobs, total_failed, total_canceled,
             total_done, total_dry_run, peak_jobs, current_jobs, unsubmitted,
             stage_in, pending, active, stage_out, failed, done)
        """

        jmid = self.get_job_manager_instance_id(GRAM5Packet.cursor)
        when = GRAM5Packet.TimestampFromTicks(float(self.data.get("C")))

        seenkey = (jmid, when)

        if GRAM5JMPacket.__seen_packets__.get(seenkey):
            return None
        else:
            GRAM5JMPacket.__seen_packets__[seenkey] = 1

        values = (
            jmid,
            self.data.get("I"),
            when,
            self.get_lifetime(),
            self.data.get("K"),
            self.data.get("L"),
            self.data.get("M"),
            self.data.get("N"),
            self.data.get("O"),
            self.data.get("P"),
            self.data.get("Q"),
            self.data.get("R"),
            self.data.get("S"),
            self.data.get("T"),
            self.data.get("U"),
            self.data.get("V"),
            self.data.get("W"),
            self.data.get("X"))
        return values

class GRAM5JobPacket(GRAM5Packet):
    """
    GRAM5 Usage Packet handler for job status packets
    """
    
    data_aggregation = {}

    def __init__(self, address, packet):
        GRAM5Packet.__init__(self, address, packet)

    @staticmethod
    def upload_many(dbclass, cursor, packets):
        """
        Upload many GRAM5Packet usage packets to the database referred to
        by the given cursor. It will also prepare the caches of id tables.

        Returns an array of bad packets
        """
        res = GRAM5Packet.upload_many(dbclass, cursor, packets)

        for pack in packets:
            if pack is not None and pack not in res:
                send_time = list(pack.send_time)
                send_time[4] = send_time[5] = 0
                send_time = tuple(send_time)

                server_id = pack.get_job_manager_instance_id_by_uuid(cursor)
                failure_code = pack.data.get('j') or 0

                agg_key = (send_time, server_id, failure_code)

                if agg_key not in GRAM5JobPacket.data_aggregation.keys():
                    GRAM5JobPacket.data_aggregation[agg_key] = 0
                GRAM5JobPacket.data_aggregation[agg_key] += 1;
        return res

    @staticmethod
    def upload_aggregation(dbclass, cursor):
        try:
            cursor.execute("SAVEPOINT gram_aggregation")
            cursor.executemany(
                """INSERT INTO gram5_aggregations_hourly(
                        aggregation_time,
                        job_manager_instance_id,
                        failure_code,
                        job_count)
                   VALUES(%s,%s,%s,%s)""",
                [(dbclass.Timestamp(*agg_key[0]), agg_key[1], agg_key[2], 
                    GRAM5JobPacket.data_aggregation[agg_key])
                    for agg_key in GRAM5JobPacket.data_aggregation.keys()])
        except Exception, e:
            print "Error uploading aggregation data: " + e.message
            cursor.execute("ROLLBACK TO SAVEPOINT gram_aggregation")
        GRAM5JobPacket.data_aggregation = {}
    
    insert_statement = '''
            INSERT INTO gram5_job_status(
                job_id,
                send_time,
                unsubmitted_timestamp,
                file_stage_in_timestamp,
                pending_timestamp,
                active_timestamp,
                failed_timestamp,
                file_stage_out_timestamp,
                done_timestamp,
                status_count,
                register_count,
                unregister_count,
                signal_count,
                refresh_count,
                failure_code,
                restart_count,
                callback_count)
            VALUES(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s)'''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A GRAM5JobPacket object

        Returns:
        Tuple containing
            (job_id, send_time,
             unsubmitted_timestamp, file_stage_in_timestamp, pending_timestamp,
             active_timestamp, failed_timestamp, file_stage_out_timestamp,
             done_timestamp, status_count, register_count, unregister_count,
             signal_count, refresh_count, failure_code, restart_count,
             callback_count)
        """
        unsubmitted_timestamp = None
        file_stage_in_timestamp = None
        pending_timestamp = None
        active_timestamp = None
        failed_timestamp = None
        file_stage_out_timestamp = None
        done_timestamp = None

        # GT-183: Usage stats server doesn't discard bad packets
        if self.data.get('B') is None or len(self.data.get('B')) != 36:
            return None

        if self.data.get('c') is not None and float(self.data.get('c')) > 1:
            unsubmitted_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("c")))
        if self.data.get('d') is not None and float(self.data.get('d')) > 1:
            file_stage_in_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("d")))
        if self.data.get('e') is not None and float(self.data.get('e')) > 1:
            pending_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("e")))
        if self.data.get('f') is not None and float(self.data.get('f')) > 1:
            active_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("f")))
        if self.data.get('g') is not None and float(self.data.get('g')) > 1:
            failed_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("g")))
        if self.data.get('h') is not None and float(self.data.get('h')) > 1:
            file_stage_out_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("h")))
        if self.data.get('i') is not None and float(self.data.get('i')) > 1:
            done_timestamp = GRAM5Packet.TimestampFromTicks(
                    float(self.data.get("i")))
        return (
            self.get_job_id(GRAM5Packet.cursor),
            dbclass.Timestamp(*self.send_time),
            unsubmitted_timestamp,
            file_stage_in_timestamp,
            pending_timestamp,
            active_timestamp,
            failed_timestamp,
            file_stage_out_timestamp,
            done_timestamp,
            self.data.get("k") or 0,
            self.data.get("l") or 0,
            self.data.get("2") or 0,
            self.data.get("m") or 0,
            self.data.get("n") or 0,
            self.data.get("j") or 0,
            self.data.get("Y") or 0,
            self.data.get("Z") or 0)

    def get_job_id(self, cursor):
        job_id = None
        job_manager_id = self.get_job_manager_instance_id_by_uuid(cursor)
        count = self.data.get("3")
        if count is None:
            count = 0

        host_count = self.data.get("b")
        if host_count is None:
            host_count = 0
        dryrun = self.data.get('a') == '1'
        client_id = self.get_client_id(cursor)
        executable_id = self.get_executable_id(cursor)
        rsl_bitfield = self.get_rsl_bitfield(cursor)
        gram5_job_file_info = self.get_file_info(cursor)
        jobtype = self.get_job_type(cursor)

        cursor.execute("""
            SELECT nextval('gram5_jobs_id_seq') as key
            """)
        job_id = cursor.fetchone()[0]

        values = (
            job_id,
            job_manager_id,
            GRAM5Packet.db_class.Timestamp(*self.send_time),
            count,
            host_count,
            dryrun,
            client_id,
            executable_id,
            rsl_bitfield,
            jobtype,
            gram5_job_file_info)

        cursor.execute('''
                INSERT INTO gram5_jobs(
                    id,
                    job_manager_id,
                    send_time,
                    count,
                    host_count,
                    dryrun,
                    client_id,
                    executable_id,
                    rsl_bitfield,
                    jobtype,
                    gram5_job_file_info)
                VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''', values)

        return job_id

    def get_client_id(self, cursor):
        host_id = None
        client_id = None

        client_ip = self.data.get('8')
        user_dn = self.data.get('9')

        if client_ip is not None:
            address = client_ip.split(':')[0]
            host_id = GRAM5Packet.dns_cache.get_host_id(address)

        values = (host_id, user_dn)

        if host_id is not None or user_dn is not None:
            client_id = GRAM5Packet.clients.get(values)

            if client_id is None:
                cursor.execute("""
                    SELECT nextval('gram5_client_id_seq') as key
                    """)
                client_id = cursor.fetchone()[0]
                values_sql = (client_id, host_id, user_dn)
                cursor.execute('''
                        INSERT INTO gram5_client(
                            id,
                            host_id,
                            dn)
                        VALUES(%s, %s, %s)''', values_sql)
                GRAM5Packet.clients[values] = client_id
        return client_id

    def get_file_info(self, cursor):
        file_info_id = None

        file_clean_up = self.data.get('o')

        file_stage_in_http = self.data.get('p')
        file_stage_in_https = self.data.get('q')
        file_stage_in_ftp = self.data.get('r')
        file_stage_in_gsiftp = self.data.get('s')

        file_stage_in_shared_http = self.data.get('t')
        file_stage_in_shared_https = self.data.get('u')
        file_stage_in_shared_ftp = self.data.get('v')
        file_stage_in_shared_gsiftp = self.data.get('w')

        file_stage_out_http = self.data.get('x')
        file_stage_out_https = self.data.get('y')
        file_stage_out_ftp = self.data.get('z')
        file_stage_out_gsiftp = self.data.get('0')

        if file_clean_up is None:
            file_clean_up = 0

        if file_stage_in_http is None:
            file_stage_in_http = 0

        if file_stage_in_https is None:
            file_stage_in_https = 0

        if file_stage_in_ftp is None:
            file_stage_in_ftp = 0

        if file_stage_in_gsiftp is None:
            file_stage_in_gsiftp = 0

        if file_stage_in_shared_http is None:
            file_stage_in_shared_http = 0

        if file_stage_in_shared_https is None:
            file_stage_in_shared_https = 0

        if file_stage_in_shared_ftp is None:
            file_stage_in_shared_ftp = 0

        if file_stage_in_shared_gsiftp is None:
            file_stage_in_shared_gsiftp = 0

        if file_stage_out_http is None:
            file_stage_out_http = 0

        if file_stage_out_https is None:
            file_stage_out_https = 0

        if file_stage_out_ftp is None:
            file_stage_out_ftp = 0
        
        if file_stage_out_gsiftp is None:
            file_stage_out_gsiftp = 0

        if file_clean_up != 0 or \
                file_stage_in_http != 0 or \
                file_stage_in_https != 0 or \
                file_stage_in_ftp != 0 or \
                file_stage_in_gsiftp != 0 or \
                file_stage_in_shared_http != 0 or \
                file_stage_in_shared_https != 0 or \
                file_stage_in_shared_ftp != 0 or \
                file_stage_in_shared_gsiftp != 0 or \
                file_stage_out_http != 0 or \
                file_stage_out_https != 0 or \
                file_stage_out_ftp != 0 or \
                file_stage_out_gsiftp != 0:
            cursor.execute("""
                SELECT nextval('gram5_job_file_info_id_seq') AS key
                """)
            file_info_id = cursor.fetchone()[0]
            values = (
                file_info_id,
                file_clean_up,
                file_stage_in_http,
                file_stage_in_https,
                file_stage_in_ftp,
                file_stage_in_gsiftp,
                file_stage_in_shared_http,
                file_stage_in_shared_https,
                file_stage_in_shared_ftp,
                file_stage_in_shared_gsiftp,
                file_stage_out_http,
                file_stage_out_https,
                file_stage_out_ftp,
                file_stage_out_gsiftp)

            cursor.execute('''
                INSERT into gram5_job_file_info(
                    id,
                    file_clean_up,
                    file_stage_in_http,
                    file_stage_in_https,
                    file_stage_in_ftp,
                    file_stage_in_gsiftp,
                    file_stage_in_shared_http,
                    file_stage_in_shared_https,
                    file_stage_in_shared_ftp,
                    file_stage_in_shared_gsiftp,
                    file_stage_out_http,
                    file_stage_out_https,
                    file_stage_out_ftp,
                    file_stage_out_gsiftp)
                VALUES(%s, %s, %s, %s, %s, %s, %s, 
                       %s, %s, %s, %s, %s, %s, %s)''',
                values)
        return file_info_id

    def get_job_type(self, cursor):
        """
        Determine the job type key which matches the job type used in this
        packet. If this job type is not defined in the table, attempt to insert
        it into the gram5_job_types table and return that id.

        Arguments:
        self -- A gram5packet.GRAM5Packet object
        cursor -- An SQL cursor to use if we need to insert this job type into
        the table

        Returns:
        An integer key to the gram5_job_types table or None if the job type
        is not defined or can't be parsed. As a side effect, this
        key may be newly defined and cached.
        """
        job_type_id = None

        job_type = self.data.get('H')

        values = (job_type,)

        job_type_id = GRAM5Packet.job_type_ids.get(job_type)

        if job_type_id == None:
            cursor.execute("SELECT nextval('gram5_job_types_id_seq') AS key")
            job_type_id = cursor.fetchone()[0]
            values = (job_type_id, job_type)
            cursor.execute('''
                INSERT into gram5_job_types(
                    id,
                    jobtype)
                VALUES(%s, %s)''',
                values)
            GRAM5Packet.job_type_ids[job_type] = job_type_id
        return job_type_id
# vim: ts=4:sw=4:syntax=python
