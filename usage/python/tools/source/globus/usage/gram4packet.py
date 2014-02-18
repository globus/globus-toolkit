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
Object definition for processing GRAM4 usage packets.
"""

from globus.usage.iptimemonitorpacket import IPTimeMonitorPacket
import time

class GRAM4Packet(IPTimeMonitorPacket):
    """
    GRAM 4 Usage Packet handler
    """
    __MAX_SCHEDULER_SIZE = 20
    def __init__(self, address, packet):
        """

        """
        IPTimeMonitorPacket.__init__(self, address, packet)
        [creation_time_millis] = self.unpack("q")
        self.creation_time = \
            tuple(
                list(
                    time.gmtime(creation_time_millis / 1000))[0:6])

        self.lrm = ''
        # Workaround a bug in GRAM service sending LRM name + char[].toString()
        # which yields a java object pointer if the LRM name is shorter than
        # __MAX_SCHEDULER_SIZE. 
        # We'll parse until we hit the byte \0, \1, or the __MAX_SCHEDULER_SIZE
        # then strip off everything afer [C if it is present
        self.lrm = self.unpack_lrm_string()
        [
            self.job_credential_endpoint_used, 
            self.file_stage_in_used,
            self.file_stage_out_used,
            self.file_clean_up_used,
            self.clean_up_hold_used
        ] = map(lambda x: (x == 1), self.unpack("5B"))
        [
            self.job_type,
            self.gt2_error_code,
            self.fault_class
        ] = self.unpack("3B")

    insert_statement = '''
            INSERT INTO gram_packets(
                component_code,
                version_code,
                send_time,
                ip_address,
                creation_time,
                scheduler_type,
                job_credential_endpoint_used,
                file_stage_in_used,
                file_stage_out_used,
                file_clean_up_used,
                clean_up_hold_used,
                job_type,
                gt2_error_code,
                fault_class)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''

    def values(self, dbclass):
        """
        Return a values tuple which matches the parameters in the
        class's insert_statement.

        Arguments:
        self -- A GRAM4Packet object

        Returns:
        Tuple containing
            (component_code, version_code, send_time, ip_address,
             creation_time, scheduler_type, job_credential_endpoint_used,
             file_stage_in_used, file_stage_out_used, file_clean_up_used,
             job_type, gt2_error_code, fault_class)

        """
        return (
            self.component_code,
            self.packet_version,
            dbclass.Timestamp(*self.send_time),
            self.ip_address,
            dbclass.Timestamp(*self.creation_time),
            self.lrm,
            self.job_credential_endpoint_used,
            self.file_stage_in_used,
            self.file_stage_out_used,
            self.file_clean_up_used,
            self.clean_up_hold_used,
            self.job_type,
            self.gt2_error_code,
            self.fault_class)

    def unpack_lrm_string(self):
        lrm_string = ''
        for _ in range(GRAM4Packet.__MAX_SCHEDULER_SIZE):
            [byte_value] = self.unpack("B")
            if byte_value > 1:
                lrm_string += chr(byte_value)
            else:
                self.packet_body_offset -= 1
                break
        return lrm_string.split("[C")[0]


