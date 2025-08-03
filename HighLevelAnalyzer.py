# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting
from enum import Enum
import re
import json


class DecoderState(Enum):
    WAITING_FOR_START_CONDITION = 1
    WAITING_FOR_DEVICE_ADDRESS = 2
    PROCESSING_DATA_WRITE_ADDRESS = 3
    PROCESSING_DATA_BYTES = 4

class AccessType(Enum):
    UNKNOWN = 1
    READ = 2
    WRITE = 3

def parse_device_address(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    else:
        return int(float(s))


class Hla(HighLevelAnalyzer):
    memory_regions = StringSetting(label='Memory regions (e.g. regionname1=0xab-0xcd, regionname2=0x1000-0x10FF)')
    i2c_7bit_device_address = StringSetting(label='7bit address of I2C EEPROM (e.g. 0x50)')
    number_of_data_address_bytes = NumberSetting(label='Number of address bytes (1 or 2 in most cases)', min_value=1)

    result_types = {
        'memoryRegion': {
            'format': '{{data.region_name}} ({{data.access_type}}{{data.count}} | {{data.duration_ms}}ms)'
        }
    }

    def __init__(self):
        self.decoder_state = DecoderState.WAITING_FOR_START_CONDITION
        self.start_time = None
        self.data_bytes = bytearray()
        self.memory_address_bytes = []
        self.memory_address = 0x0000  # assuming address zero if no address was written
        self.access_type = AccessType.UNKNOWN

        pattern = r"(?P<name>\w+)\s*=\s*0x(?P<start>[0-9a-fA-F]+)\s*-\s*0x(?P<end>[0-9a-fA-F]+)"
        matches = re.finditer(pattern, str(self.memory_regions))
        self.regions = {}
        for match in matches:
            name = match.group("name")
            start = int(match.group("start"), 16)
            end = int(match.group("end"), 16)
            self.regions[name] = {"start": start, "end": end}

        print("Memory regions:")
        print(json.dumps(self.regions, sort_keys=False, indent=5))

        self.i2c_7bit_device_address = parse_device_address(str(self.i2c_7bit_device_address))
        print("Device address:", hex(self.i2c_7bit_device_address))
        print("Data address bytes: ", int(self.number_of_data_address_bytes))

    def get_region_name(self, memory_address: int):
        region_name = None
        for name, region in self.regions.items():
            if region['start'] <= memory_address <= region['end']:
                region_name = name
                break
        return region_name

    def check_EEPROM_access(self, region_name, memory_address, byte_count) -> str:
        messages = []
        if region_name is None:
            messages.append(f"{hex(memory_address)} not inside memory region")
            # check if it read/writes into other region
            for name, region in self.regions.items():
                if memory_address < region['start'] <=  memory_address + byte_count:
                    messages.append(f"Overlapping '{name}'")
        else:
            if (memory_address + byte_count - 1) > self.regions[region_name]['end']:
                messages.append(f"Accessing memory beyond region end address ({hex(memory_address)} + {byte_count} bytes)")
        return " | ".join(messages)

    def decode(self, frame: AnalyzerFrame):
        # START_CONDITION
        if self.decoder_state == DecoderState.WAITING_FOR_START_CONDITION:
            if frame.type == 'start':
                self.decoder_state = DecoderState.WAITING_FOR_DEVICE_ADDRESS
                self.start_time = frame.start_time
                self.data_bytes = bytearray()
                self.memory_address_bytes = []

        # DEVICE_ADDRESS
        elif self.decoder_state == DecoderState.WAITING_FOR_DEVICE_ADDRESS:
            if frame.type == 'address' and frame.data['ack'] == True and self.i2c_7bit_device_address == frame.data['address'][0]:
                if frame.data['read'] == True:
                    self.decoder_state = DecoderState.PROCESSING_DATA_BYTES
                    self.access_type = AccessType.READ
                else:
                    self.decoder_state = DecoderState.PROCESSING_DATA_WRITE_ADDRESS
                    self.access_type = AccessType.WRITE
            else:
                self.decoder_state = DecoderState.WAITING_FOR_START_CONDITION

        # DATA ADDRESS
        elif self.decoder_state == DecoderState.PROCESSING_DATA_WRITE_ADDRESS:
            if frame.type == 'data' and frame.data['ack'] == True:
                self.memory_address_bytes.append(frame.data['data'][0])
                if len(self.memory_address_bytes) >= int(self.number_of_data_address_bytes):
                    self.memory_address = int.from_bytes(self.memory_address_bytes, byteorder='big')
                    self.decoder_state = DecoderState.PROCESSING_DATA_BYTES
            else:
                self.decoder_state = DecoderState.WAITING_FOR_START_CONDITION

        # DATA_BYTES
        elif self.decoder_state == DecoderState.PROCESSING_DATA_BYTES:
            if frame.type == 'start': # repeated start condition
                self.memory_address += len(self.data_bytes)  # if bytes have been written and then a read follows (with repeated start)
                self.decoder_state = DecoderState.WAITING_FOR_DEVICE_ADDRESS
            elif frame.type == 'data':
                self.data_bytes.extend(frame.data['data'])
            elif frame.type == 'stop':
                region_name = self.get_region_name(self.memory_address)
                warning = self.check_EEPROM_access(region_name, self.memory_address, len(self.data_bytes))

                memory_address = self.memory_address
                self.memory_address += len(self.data_bytes)  # prepare for next read (without writing address)

                self.decoder_state = DecoderState.WAITING_FOR_START_CONDITION

                return AnalyzerFrame('memoryRegion', self.start_time, frame.end_time, {
                    'region_name': region_name if region_name is not None else '???',
                    'memory_address': memory_address,
                    'access_type': 'R' if self.access_type == AccessType.READ else 'W',
                    'count': len(self.data_bytes),
                    'duration_ms': round(float(frame.end_time - self.start_time) * 1000, 3),  # ms
                    'data': self.data_bytes,
                    'warning': warning
                })
            else:
                self.decoder_state = DecoderState.WAITING_FOR_START_CONDITION
