# Feedback:
# could not figure out where to import GraphTime from, had to check our unit tests.
# unit tests or attached debugger would save many hours
# auto-rerun on save would be nice
# auto or manual console clear would be nice
# some way of displaying numbers as hex in the bubbles, besides converting to string.
# sometimes my format strings don't apply at all. reloading the analyzer fixes this.
# can't display quote character in resulting strings, they get html encoded. (nevermind, this just requires and extra set of {} in the format string to display the string as raw.)
# we have way too much data to effectively display in the data table or the graph display, we need to support efficient object display somehow.

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

from MessageHandling import *

# https://www.embedded.com/usb-type-c-and-power-delivery-101-power-delivery-protocol/
# official documentation: https://www.usb.org/document-library/usb-power-delivery


# TODO / Future Features:
# add support for extended headers and data blocks
# decode all vendor data objects. (header is done)
# ID Header VDO, Cert Stat VDO, Product VDO UFP VDO 1/2, DFP VDO, Passive cable VDO, Active Cable VDO 1/2, AMA VDO, VPD VDO,Discover SVIDs Responder VDO,

preamble = [0, 1] * 32

symbol_table = {
    0x0: [1, 1, 1, 1, 0],
    0x1: [0, 1, 0, 0, 1],
    0x2: [1, 0, 1, 0, 0],
    0x3: [1, 0, 1, 0, 1],
    0x4: [0, 1, 0, 1, 0],
    0x5: [0, 1, 0, 1, 1],
    0x6: [0, 1, 1, 1, 0],
    0x7: [0, 1, 1, 1, 1],
    0x8: [1, 0, 0, 1, 0],
    0x9: [1, 0, 0, 1, 1],
    0xA: [1, 0, 1, 1, 0],
    0xB: [1, 0, 1, 1, 1],
    0xC: [1, 1, 0, 1, 0],
    0xD: [1, 1, 0, 1, 1],
    0xE: [1, 1, 1, 0, 0],
    0xF: [1, 1, 1, 0, 1],
    'Sync-1': [1, 1, 0, 0, 0],
    'Sync-2': [1, 0, 0, 0, 1],
    'RST-1': [0, 0, 1, 1, 1],
    'RST-2': [1, 1, 0, 0, 1],
    'EOP': [0, 1, 1, 0, 1],
    'Reserved_1': [0, 0, 0, 0, 0],
    'Reserved_2': [0, 0, 0, 0, 1],
    'Reserved_3': [0, 0, 0, 1, 0],
    'Reserved_4': [0, 0, 0, 1, 1],
    'Reserved_5': [0, 0, 1, 0, 0],
    'Reserved_6': [0, 0, 1, 0, 1],
    'Sync-3': [0, 0, 1, 1, 0],
    'Reserved_7': [0, 1, 0, 0, 0],
    'Reserved_8': [0, 1, 1, 0, 0],
    'Reserved_9': [1, 0, 0, 0, 0],
    'Reserved_10': [1, 1, 1, 1, 1],
}

ordered_sets = {
    'SOP': ['Sync-1', 'Sync-1', 'Sync-1', 'Sync-2'],
    'SOP\'': ['Sync-1', 'Sync-1', 'Sync-3', 'Sync-3'],
    'SOP\'\'': ['Sync-1', 'Sync-3', 'Sync-1', 'Sync-3'],
    'Hard Reset': ['RST-1', 'RST-1', 'RST-1', 'RST-2'],
    'Cable Reset': ['RST-1', 'Sync-1', 'RST-1', 'Sync-3'],
    'SOP\'_debug': ['Sync-1', 'RST-2', 'RST-2', 'Sync-3'],
    'SOP\'\'_debug': ['Sync-1', 'RST-2', 'Sync-3', 'Sync-2']
}

data_commands = {
    0b00000: 'Reserved',
    0b00001: 'Source_Capabilities',
    0b00010: 'Request',
    0b00011: 'BIST',
    0b00100: 'Sink_Capabilities',
    0b00101: 'Battery_Status',
    0b00110: 'Alert',
    0b00111: 'Get_Country_Info',
    0b01000: 'Enter_USB',
    0b01001: 'Reserved',
    0b01010: 'Reserved',
    0b01011: 'Reserved',
    0b01100: 'Reserved',
    0b01101: 'Reserved',
    0b01110: 'Reserved',
    0b01111: 'Vendor_Defined',
    0b10000: 'Reserved',
    0b10001: 'Reserved',
    0b10010: 'Reserved',
    0b10011: 'Reserved',
    0b10100: 'Reserved',
    0b10101: 'Reserved',
    0b10110: 'Reserved',
    0b10111: 'Reserved',
    0b11000: 'Reserved',
    0b11001: 'Reserved',
    0b11010: 'Reserved',
    0b11011: 'Reserved',
    0b11100: 'Reserved',
    0b11101: 'Reserved',
    0b11110: 'Reserved',
    0b11111: 'Reserved'
}

control_commands = {
    0b00000: 'Reserved',
    0b00001: 'GoodCRC',
    0b00010: 'GotoMin',
    0b00011: 'Accept',
    0b00100: 'Reject',
    0b00101: 'Ping',
    0b00110: 'PS_RDY',
    0b00111: 'Get_Source_Cap',
    0b01000: 'Get_Sink_Cap',
    0b01001: 'DR_Swap',
    0b01010: 'PR_Swap',
    0b01011: 'VCONN_Swap',
    0b01100: 'Wait',
    0b01101: 'Soft_Reset',
    0b01110: 'Data_Reset',
    0b01111: 'Data_Reset_Complete',
    0b10000: 'Not_Supported',
    0b10001: 'Get_Source_Cap_Extended',
    0b10010: 'Get_Status',
    0b10011: 'FR_Swap',
    0b10100: 'Get_PPS_Status',
    0b10101: 'Get_Country_Codes',
    0b10110: 'Get_Sink_Cap_extended',
    0b10111: 'Reserved',
    0b11000: 'Reserved',
    0b11001: 'Reserved',
    0b11010: 'Reserved',
    0b11011: 'Reserved',
    0b11100: 'Reserved',
    0b11101: 'Reserved',
    0b11110: 'Reserved',
    0b11111: 'Reserved',
}

power_port_role = {
    0: 'Sink',
    1: 'Source'
}
cable_plug = {
    0: 'from DFP or UFP',
    1: 'from cable plug'
}

revision = {
    0: '1.0',
    1: '2.0',
    2: 'Reserved',
    3: 'Reserved'
}

port_data_role = {
    0: 'UFP',
    1: 'DFP'
}


class Word():
    start_time = None
    end_time = None
    data = None

    def __init__(self, start_time, end_time, data):
        self.start_time = start_time
        self.end_time = end_time
        self.data = data


class Hla(HighLevelAnalyzer):

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'preamble': {'format': 'Preamble'},
        'ordered_set': {'format': 'Start Of Packet: {{data.ordered_set}}'},
        'header': {'format': '# of Objects: {{data.number_of_objects}} Message ID: {{data.message_id}} Command Code: {{data.command_code}} Spec Revision: {{data.spec_revision}}'},
        'source_fixed_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; Dual Role Power: {{data.dual_role_power}}; USB Suspend Supported: {{data.usb_suspend_supported}}; USB Communications Supported: {{data.usb_communications_capable}} Dual Role Data: {{data.dual_role_data}}; Unchecked Extended Messages Supported: {{data.unchecked_extended_messages_supported}}; Peak Current: {{data.peak_current}}; Voltage (50mV units): {{data.voltage_50mv_units}}; Maximum Current (10mA units): {{data.maximum_current_10ma_units}}'},
        'source_variable_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_50mv_units: {{data.maximum_voltage_50mv_units}}; minimum_voltage_50mv_units: {{data.minimum_voltage_50mv_units}}; maximum_current_10ma_units: {{data.maximum_current_10ma_units}}'},
        'source_battery_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_50mv_units: {{data.maximum_voltage_50mv_units}}; minimum_voltage_50mv_units: {{data.minimum_voltage_50mv_units}}; maximum_allowable_power_250mw_units: {{data.maximum_allowable_power_250mw_units}}'},
        'source_programmable_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_100mv_units: {{data.maximum_voltage_100mv_units}}; minimum_voltage_100mv_units: {{data.minimum_voltage_100mv_units}}; maximum_current_50ma_units: {{data.maximum_current_50ma_units}}'},
        'sink_fixed_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; Dual Role Power: {{data.dual_role_power}}; USB Suspend Supported: {{data.usb_suspend_supported}}; Unconstrained Power: {{data.unconstrained_power}}; USB Communications Supported: {{data.usb_communications_capable}}; Dual Role Data: {{data.dual_role_data}}; Fast Role Swap Required Current: {{data.fast_role_swap_required_current}}; Voltage (50mV units): {{data.voltage_50mv_units}}; Operational Current (10mA units): {{data.operational_current_10ma_units}}'},
        'sink_variable_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_50mv_units: {{data.maximum_voltage_50mv_units}}; minimum_voltage_50mv_units: {{data.minimum_voltage_50mv_units}}; maximum_current_10ma_units: {{data.maximum_current_10ma_units}}'},
        'sink_battery_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_50mv_units: {{data.maximum_voltage_50mv_units}}; minimum_voltage_50mv_units: {{data.minimum_voltage_50mv_units}}; maximum_allowable_power_250mw_units: {{data.maximum_allowable_power_250mw_units}}'},
        'sink_programmable_supply_pdo': {'format': '[{{data.index}}] [{{data.raw}}] {{data.data_object_type}}; {{data.pdo_type}}; maximum_voltage_100mv_units: {{data.maximum_voltage_100mv_units}}; minimum_voltage_100mv_units: {{data.minimum_voltage_100mv_units}}; maximum_current_50ma_units: {{data.maximum_current_50ma_units}}'},
        'bdo': {'format': '{{data.data_object_type}} BIST Mode: {{data.bist_mode}}'},
        'fixed_supply_rdo': {'format': '{{data.data_object_type}} Object Position: {{data.object_position}}; Giveback Flag: {{data.giveback_flag}}; Capability Missmatch: {{data.capability_mismatch}}; usb_communications_capable: {{data.usb_communications_capable}}; no_usb_suspend: {{data.no_usb_suspend}}; unchunked_extended_messages_supported: {{data.unchunked_extended_messages_supported}}; operating_current_10ma_units: {{data.operating_current_10ma_units}}; maximum_operating_current_10ma_units: {{data.maximum_operating_current_10ma_units}}; '},
        'variable_supply_rdo': {'format': '{{data.data_object_type}} Object Position: {{data.object_position}}; Giveback Flag: {{data.giveback_flag}}; Capability Missmatch: {{data.capability_mismatch}}; usb_communications_capable: {{data.usb_communications_capable}}; no_usb_suspend: {{data.no_usb_suspend}}; unchunked_extended_messages_supported: {{data.unchunked_extended_messages_supported}}; operating_current_10ma_units: {{data.operating_current_10ma_units}}; maximum_operating_current_10ma_units: {{data.maximum_operating_current_10ma_units}}; '},
        'battery_rdo': {'format': '{{data.data_object_type}} object_position: {{data.object_position}}; giveback_flag: {{data.giveback_flag}}; capability_mismatch: {{data.capability_mismatch}}; usb_communications_capable: {{data.usb_communications_capable}}; no_usb_suspend: {{data.no_usb_suspend}}; unchunked_extended_messages_supported: {{data.unchunked_extended_messages_supported}}; operating_power_250mw_units: {{data.operating_power_250mw_units}}; maximum_operating_power_250mw_units: {{data.maximum_operating_power_250mw_units}}'},
        'programmable_supply_rdo': {'format': '{{data.data_object_type}} object_position: {{data.object_position}}; capability_mismatch: {{data.capability_mismatch}}; usb_communications_capable: {{data.usb_communications_capable}}; no_usb_suspend: {{data.no_usb_suspend}}; unchunked_extended_messages_supported: {{data.unchunked_extended_messages_supported}}; output_voltage_20mV_units: {{data.output_voltage_20mV_units}}; operating_current_50ma_unites: {{data.operating_current_50ma_unites}}'},
        'structured_header_vdo': {'format': '{{data.data_object_type}} vendor_id: {{data.vendor_id}}; vdm_type: {{data.vdm_type}}; structured_vdm_version: {{data.structured_vdm_version}}; object_position: {{data.object_position}}; command_type: {{data.command_type}}; command: {{data.command}}'},
        'unstructured_header_vdo': {'format': '{{data.data_object_type}} vendor_id: {{data.vendor_id}}; vdm_type: {{data.vdm_type}}'},
        'bsdo': {'format': '{{data.data_object_type}} invalid_battery_reference: {{data.invalid_battery_reference}}; battery_is_present: {{data.battery_is_present}}; battery_charging_status: {{data.battery_charging_status}}'},
        'ado': {'format': '{{data.data_object_type}} fixed_batteries: {{data.fixed_batteries}}; hot_swappable_batteries: {{data.hot_swappable_batteries}}; battery_status_change_event: {{data.battery_status_change_event}}; ocp_event: {{data.ocp_event}}; otp_event: {{data.otp_event}}; operating_condition_change: {{data.operating_condition_change}}; source_input_change: {{data.source_input_change}}; ovp_event: {{data.ovp_event}}'},
        'ccdo': {'format': '{{data.data_object_type}} country_code: {{data.country_code}}'},
        'eudo': {'format': '{{data.data_object_type}} usb_mode: {{data.usb_mode}}; usb4_drd: {{data.usb4_drd}}; usb3_drd: {{data.usb3_drd}}; cable_speed: {{data.cable_speed}}; cable_type: {{data.cable_type}}; cable_current: {{data.cable_current}}; pcie_support: {{data.pcie_support}}; dp_support: {{data.dp_support}}; tbt_support: {{data.tbt_support}}; host_present: {{data.host_present}}'},
        'object': {'format': '{{data.index}} {{data.data}}'},
        'crc': {'format': 'CRC: {{data.crc}} ({{data.crc_valid}})'},
        'eop': {'format': 'end of packet'},
        'error': { 'format': 'error: {{data.error}} [{{data.raw}}]' }
    }

    def __init__(self):
        self.source_capabilities_pdo_types = {}
        self.pending_frames = []

        self.engine = self.state_machine()
        self.engine.send(None)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        try:
            output_frame = self.engine.send(frame)
            if output_frame is not None:
                return output_frame

        except StopIteration:
            return

    def pop_pending_frame(self):
        if len(self.pending_frames) > 0:
            frame = self.pending_frames[0]
            self.pending_frames = self.pending_frames[1:]
            return frame
        else:
            return None

    def state_machine(self):
        while True:
            preamble_start = None
            preamble_end = None
            preamble_found = False

            while not preamble_found:
                leftover_preamble = preamble
                preamble_read = []

                for x in range(len(preamble)):
                    frame = self.pop_pending_frame()
                    if frame == None:
                        frame = yield

                    if frame.data['data'] != leftover_preamble[0]:
                        # Store all frame except first one to retry a pattern matching on them
                        self.pending_frames.extend(preamble_read[1:] + [frame])
                        frame = yield AnalyzerFrame('error', frame.start_time, frame.end_time, {'error': f"Invalid preamble.", 'raw': frame.data['data']})
                        self.pending_frames.extend([frame])
                        break

                    leftover_preamble = leftover_preamble[1:]
                    preamble_read.extend([frame])

                    if x == 0:
                        preamble_start = frame.start_time

                    if x == len(preamble)-1:
                        preamble_end = frame.end_time
                        preamble_found = True

            print(f'Preamble')
            frame = yield AnalyzerFrame('preamble', preamble_start, preamble_end, {})

            ordered_set_word = yield from self.get_bits(frame, 20)
            ordered_set_cmd = self.decode_ordered_set(ordered_set_word.data)
            print(ordered_set_cmd)
            frame = yield AnalyzerFrame('ordered_set', ordered_set_word.start_time, ordered_set_word.end_time, {'ordered_set': ordered_set_cmd})

            if ordered_set_cmd not in ['SOP', 'SOP\'', 'SOP\'\'', 'SOP\'_debug', 'SOP\'\'_debug']:
                self.pending_frames.extend([frame])
                continue

            header_word = yield from self.get_bits(frame, 20)
            header_decoded = self.bits_to_bytes(header_word.data, 2)
            header_int = int.from_bytes(header_decoded, "little")
            object_count = (header_int >> 12) & 0x07
            header_data = self.decode_header(header_int, ordered_set_cmd)
            crc_data = header_decoded

            print(header_data)
            frame = yield AnalyzerFrame('header', header_word.start_time, header_word.end_time, header_data)

            for object_index in range(object_count):
                object_word = yield from self.get_bits(frame, 40)
                object_decoded = self.bits_to_bytes(object_word.data, 4)
                crc_data += object_decoded
                object_int = int.from_bytes(object_decoded, "little")
                data_object_data = {
                    'index': object_index, 'data': hex(object_int)}
                data_object_type = 'object'
                if header_data['command_code'] == 'Source_Capabilities':
                    frame_type, data_object_data = decode_source_power_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                    self.source_capabilities_pdo_types[object_index] = data_object_data['pdo_type']
                elif header_data['command_code'] == 'Request':
                    object_position = (object_int >> 28) & 0x7
                    if len(self.source_capabilities_pdo_types) >= object_position:
                        source_capabilities_pdo_type = self.source_capabilities_pdo_types[object_position-1]
                        frame_type, data_object_data = decode_request_data_object(
                            object_int, source_capabilities_pdo_type)
                        data_object_type = frame_type
                        data_object_data['index'] = object_index
                        data_object_data['raw'] = hex(object_int)
                    else:
                        data_object_type = 'error'
                        data_object_data = { 'error': '"Request" for object position "{}" received without "Source_Capabilities" message observed first'.format(str(object_position)), 'raw': hex(object_int) }
                elif header_data['command_code'] == 'BIST':
                    frame_type, data_object_data = decode_bist_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Sink_Capabilities':
                    frame_type, data_object_data = decode_sink_power_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Battery_Status':
                    frame_type, data_object_data = decode_battery_status_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Alert':
                    frame_type, data_object_data = decode_alert_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Get_Country_Info':
                    frame_type, data_object_data = decode_get_country_info_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Enter_USB':
                    frame_type, data_object_data = decode_enter_usb_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                elif header_data['command_code'] == 'Vendor_Defined' and object_index == 0:
                    frame_type, data_object_data = decode_vendor_header_data_object(
                        object_int)
                    data_object_type = frame_type
                    data_object_data['index'] = object_index
                    data_object_data['raw'] = hex(object_int)
                # TODO: support all vendor requests
                # TODO: support extended headers, and data blocks
                print(data_object_data)
                frame = yield AnalyzerFrame(data_object_type, object_word.start_time, object_word.end_time, data_object_data)

            crc_word = yield from self.get_bits(frame, 40)
            crc_decoded = self.bits_to_bytes(crc_word.data, 4)
            crc_int = int.from_bytes(crc_decoded, "little")
            crc_data += crc_decoded
            crc_valid = self.crc32(crc_data) == 0xC704DD7B

            print(f'crc 0x{crc_int:08x} {"valid" if crc_valid else "invalid"}')

            frame = yield AnalyzerFrame('crc', crc_word.start_time, crc_word.end_time, {'crc': hex(crc_int), 'crc_valid': crc_valid})

            eop_word = yield from self.get_bits(frame, 5)
            if eop_word.data == list(reversed(symbol_table['EOP'])):
                frame = yield AnalyzerFrame('eop', eop_word.start_time, eop_word.end_time, {})
            else:
                frame = yield AnalyzerFrame('error', eop_word.start_time, eop_word.end_time, {'error': 'Expected EOP not found.'})

            self.pending_frames.extend([frame])

    def get_bits(self, first_frame, num_bits):
        word_start = None
        word_end = None
        raw_bits = []

        for x in range(num_bits):
            frame = first_frame
            if x > 0:
                frame = yield
            if x == 0:
                word_start = frame.start_time
            if x == num_bits-1:
                word_end = frame.end_time

            raw_bits.extend([frame.data['data']])

        return Word(word_start, word_end, raw_bits)

    def frame_to_bits(self, frame):
        bits = []
        for x in range(frame_bits):
            bits.append((frame >> x) & 0x01)
        return bits

    def bits_to_bytes(self, bits, num_bytes):
        decoded = bytearray(num_bytes)
        # get everything into a huge array of bits
        for i in range(num_bytes):
            # convert 10 bits to 8 bits, save in decoded.
            fiver = bits[:5]
            nibble = self.decode_symbol(fiver)
            bits = bits[5:]
            decoded[i] = nibble
            nibble = self.decode_symbol(bits[:5])
            bits = bits[5:]
            decoded[i] |= nibble << 4
        return decoded

    def byte_to_bits(self, byte):
        bits = []
        for x in range(8):
            bits.append((byte >> x) & 0x01)
        return bits

    @staticmethod
    def decode_symbol(bits):
        return [k for k, v in symbol_table.items() if v == list(reversed(bits))][0]

    def decode_ordered_set(self, bits):
        symbols = [ self.decode_symbol(bits[x:x+5]) for x in range(0, len(bits), 5)]

        for ordered_set, codes in ordered_sets.items():
            if sum([symbols[i] == codes[i] for i in range(4)]) >= 3:
                return ordered_set

        return 'Unknown SOP*'

    def decode_header(self, header, sop_type):
        number_of_objects = (header >> 12) & 0x07
        message_id = (header >> 9) & 0x07
        spec_revision = (header >> 6) & 0x03
        command_code = header & 0x1F
        if number_of_objects == 0:
            if command_code in control_commands:
                command_code = control_commands[command_code]
        else:
            if command_code in data_commands:
                command_code = data_commands[command_code]

        data = {
            'number_of_objects': number_of_objects,
            'message_id': message_id,
            'spec_revision': spec_revision,
            'command_code': str(command_code)
        }

        if sop_type == 'SOP':
            _power_port_role = (header >> 8) & 0x01
            _port_data_role = (header >> 5) & 0x01
            data['power_port_role'] = power_port_role[_power_port_role]
            data['port_data_role'] = port_data_role[_port_data_role]
        else:
            _cable_plug = (header >> 8) & 0x01
            data['cable_plug'] = cable_plug[_cable_plug]
        return data

    @staticmethod
    def crc32(data):
        crc = 0xffffffff
        poly = 0x04C11DB6

        for b in data:
            for i in range(8):
                newbit = ((crc >> 31) ^ ((b >> i) & 1)) & 1
                if newbit:
                    newword = poly
                else:
                    newword = 0
                rl_crc = (crc << 1) | newbit
                crc = (rl_crc ^ newword) & 0xFFFFFFFF

        return crc
