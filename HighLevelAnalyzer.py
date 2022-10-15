# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions
'''
This High level Analyzer is displaying information that is exchanged between an STUSB4500 and an MCU (like an Arduino) on the I2C.
It will decode (as much as possible) the data that is read/written to a register on the STUSB4500. With data that is read from the STUSB4500
the register, it will try to decode what is known or else the raw received data is displayed. Also the NVM data is provided only as raw data.

Finding the exact right description for each register is a HUGE challenge. Different documentation, source file, header files are not 100%
in sync, but this is the best I could get to (for now). Who knows what we learn in the future.

For analysing the data the USB-PD data between de STUSB4500- SINK and USB-PD power supply there is already another HLA
https://github.com/saleae/hla-usb-pd. This can be selected as extension in Saleae

October 2022, version 1.0.0
Paul van Haastrecht

'''
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# Registers with decoders

ALERT_STATUS_1              = '0xb'         # read/decode only
ALERT_STATUS_1_MASK         = '0xc'
PORT_STATUS_1               = '0xe'         # read/decode only
TYPEC_MONITORING_STATUS_0   = '0xf'         # read and clear
TYPEC_MONITORING_STATUS_1   = '0x10'        # read/decode only
CC_STATUS                   = '0x11'        # read/decode only
CC_HW_FAULT_STATUS_0        = '0x12'        # read and clear
CC_HW_FAULT_STATUS_1        = '0x13'        # read/decode only
PD_TYPEC_STATUS             = '0x14'        # read and clear
TYPEC_STATUS                = '0x15'        # read/decode only
PRT_STATUS                  = '0x16'        # read and clear
PD_COMMAND_CTRL             = '0x1a'        # read and clear
MONITORING_CTRL_0           = '0x20'
MONITORING_CTRL_2           = '0x22'
RESET_CTRL                  = '0x23'
VBUS_DISCHARGE_TIME_CTRL    = '0x25'
VBUS_DISCHARGE_CTRL         = '0x26'
VBUS_CTRL                   = '0x27'        # read/decode only
PE_FSM                      = '0x29'        # read/decode only
GPIO_SW_GPIO                = '0x2d'
TX_HEADER_LOW               = '0x51'
DPM_PDO_NUMB                = '0x70'
DPM_SNK_PDO1_0              = '0x85'        # > 0x88
DPM_SNK_PDO2_0              = '0x89'        # > 0x8C
DPM_SNK_PDO3_0              = '0x8d'        # > 0x90
RDO_REG_STATUS_0            = '0x91'        # read/decode only
FTP_CUST_PASSWORD_REG       = '0x95'
FTP_CTRL_0                  = '0x96'
FTP_CTRL_1                  = '0x97'

# all known STUSB4500 register names (also those without decoder)
STUSB_Registers = {
    '0x6' : 'BCD_TYPEC_REV_LOW: ',            # read only
    '0x7' : 'BCD_TYPEC_REV_HIGH: ',           # read only
    '0x8' : 'BCD_USPD_REV_LOW: ',             # read only
    '0x9' : 'BCD_USPD_REV_HIGH: ',            # read only
    '0xa' : 'DEVICE_CAPAB_HIGH: ',            # read only
    '0xb' : 'ALERT_STATUS_1: ',               # read only
    '0xc' : 'ALERT_STATUS_1_MASK: ',
    '0xd' : 'PORT_STATUS_0: ',                # read only
    '0xe' : 'PORT_STATUS_1: ',                # read only
    '0xf' : 'TYPEC_MONITORING_STATUS_0: ',
    '0x10': 'TYPEC_MONITORING_STATUS_1: ',    # read only
    '0x11': 'CC_STATUS: ',                    # read only
    '0x12': 'CC_HW_FAULT_STATUS_0: ',
    '0x13': 'CC_HW_FAULT_STATUS_1: ',         # read only
    '0x14': 'PD_TYPEC_STATUS: ',
    '0x15': 'TYPEC_STATUS: ',                 # read only
    '0x16': 'PRT_STATUS: ',
    '0x1a': 'PD_COMMAND_CTRL: ',
    '0x20': 'MONITORING_CTRL_0: ',
    '0x22': 'MONITORING_CTRL_2: ',
    '0x23': 'RESET_CTRL: ',
    '0x25': 'VBUS_DISCHARGE_TIME_CTRL: ',
    '0x26': 'VBUS_DISCHARGE_CTRL: ',
    '0x27': 'VBUS_CTRL: ',                    # read only
    '0x29': 'PE_FSM: ',                       # read only
    '0x2d': 'GPIO_SW_GPIO: ',
    '0x2f': 'Device_ID: ',                    # read only
    '0x31': 'RX_HEADER_LOW: ',                # read only
    '0x32': 'RX_HEADER_HIGH: ',               # read only
    '0x33': 'RX_DATA_OBJ1_0: ',               # read only
    '0x34': 'RX_DATA_OBJ1_1: ',               # read only
    '0x35': 'RX_DATA_OBJ1_2: ',               # read only
    '0x36': 'RX_DATA_OBJ1_3: ',               # read only
    '0x37': 'RX_DATA_OBJ2_0: ',               # read only
    '0x38': 'RX_DATA_OBJ2_1: ',               # read only
    '0x39': 'RX_DATA_OBJ2_2: ',               # read only
    '0x3a': 'RX_DATA_OBJ2_3: ',               # read only
    '0x3b': 'RX_DATA_OBJ3_0: ',               # read only
    '0x3c': 'RX_DATA_OBJ3_1: ',               # read only
    '0x3d': 'RX_DATA_OBJ3_2: ',               # read only
    '0x3e': 'RX_DATA_OBJ3_3: ',               # read only
    '0x3f': 'RX_DATA_OBJ4_0: ',               # read only
    '0x40': 'RX_DATA_OBJ4_1: ',               # read only
    '0x41': 'RX_DATA_OBJ4_2: ',               # read only
    '0x42': 'RX_DATA_OBJ4_3: ',               # read only
    '0x43': 'RX_DATA_OBJ5_0: ',               # read only
    '0x44': 'RX_DATA_OBJ5_1: ',               # read only
    '0x45': 'RX_DATA_OBJ5_2: ',               # read only
    '0x46': 'RX_DATA_OBJ5_3: ',               # read only
    '0x47': 'RX_DATA_OBJ6_0: ',               # read only
    '0x48': 'RX_DATA_OBJ6_1: ',               # read only
    '0x49': 'RX_DATA_OBJ6_2: ',               # read only
    '0x4a': 'RX_DATA_OBJ6_3: ',               # read only
    '0x4b': 'RX_DATA_OBJ6_0: ',               # read only
    '0x4c': 'RX_DATA_OBJ6_1: ',               # read only
    '0x4d': 'RX_DATA_OBJ6_2: ',               # read only
    '0x4e': 'RX_DATA_OBJ6_3: ',               # read only
    '0x51': 'TX_HEADER_LOW: ',
    '0x52': 'TX_HEADER_HIGH: ',               # read / write but no description that it does
    '0x53': 'RW_BUFFER: ',
    '0x70': 'DPM_PDO_NUMB: ',
    '0x85': 'SNK_PDO1_0: ',
    '0x89': 'SNK_PDO2_0: ',
    '0x8d': 'SNK_PDO3_0: ',
    '0x91': 'RDO_REG_STATUS_0: ',             # read / write Requested Data Object (what is agreed)
    '0x92': 'RDO_REG_STATUS_1: ',             # read / write
    '0x93': 'RDO_REG_STATUS_2: ',             # read / write
    '0x94': 'RDO_REG_STATUS_3: ',             # read / write
    '0x95': 'PASSWORD_REG: ',                 # NVM access control
    '0x96': 'CTRL_0: ',                       # NVM control
    '0x97': 'CTRL_1: '                        # NVM control
}

""" Password register """
FTP_CUST_PASSWORD   = '0x47'     # enable NVM access

""" control 0 register """
FTP_CUST_PWR        = 7          # 0x80
FTP_CUST_RST_N      = 6          # 0x40 (1 = NO reset)
FTP_CUST_REQ        = 4          # 0x10 (Access request to NVM in customer mode)

Dec_control0_sect = {
    0b000: 'SECTOR_NVM_0',
    0b001: 'SECTOR_NVM_1',
    0b010: 'SECTOR_NVM_2',
    0b011: 'SECTOR_NVM_3',
    0b100: 'SECTOR_NVM_4'
}

""" control 1 register """
Dec_control1_opcode = {
    0b000: 'Read',
    0b001: 'Write_to_PL',
    0b010: 'Write_to_Erase',
    0b011: 'Write_out_PL',
    0b100: 'Write_out_Erase',
    0b101: 'Erase_sector',
    0b110: 'Word_to_EEPROM',
    0b111: 'Soft Program'
}

Dec_control1_sect = {
    0b00000: 'No_Sector',
    0b00001: 'SECTOR_NVM_0',
    0b00010: 'SECTOR_NVM_1',
    0b00100: 'SECTOR_NVM_2',
    0b01000: 'SECTOR_NVM_3',
    0b10000: 'SECTOR_NVM_4'
}

""" Alert register & mask """
PRT_STATUS_AL               = 0x1
CC_HW_FAULT_STATUS_AL       = 0x10
TYPEC_MONITORING_STATUS_AL  = 0x20
PORT_STATUS_AL              = 0x40

''' TYPEC_MONITORING_STATUS_0 '''
VBUS_VALID_SNK_TRANS        = 0x02
VBUS_VSAFE0V_TRANS          = 0x04
VBUS_READY_TRANS            = 0x08
VBUS_LOW_STATUS             = 0x10
VBUS_HIGH_STATUS            = 0x20

''' TYPEC_MONITORING_STATUS_1 '''
VBUS_READY                  = 0x08  # 0: VBUS disconnected 1: VBUS connected
VBUS_VSAFE0V                = 0x04  # 0: VBUS > 0.8V, 1: < 0.8V
VBUS_VALID_SNK              = 0x02  # 0: VBUS < 1.9 V or 3.5 V  1: VBUS > 1.9 V or 3.5 V (depending of VBUS_SNK_DISC_THRESHOLD value)

''' CC_STATUS '''
LOOKING_4_CONNECTION        = 0x20  # 0: (NOT_LOOKING) 1: Looking
CONNECT_RESULT              = 0x10  # 0: reserved  1: (PRESENT_RD) The device is presenting Rd.
# CC2_STATE: (available when CONNECT_result =1) >> 2 & 0x3
# This field returns 00b if (LOOKING_4_CONNECTION=1)
SNK_CC2_Default             = 0x1   # (Above minimum vRd-Connect)
SNK_CC2_Power1_5            = 0x2   # (Above minimum vRd-Connect)
SNK_CC2_Power3_0            = 0x3   # (Above minimum vRd-Connect)
# CC1_STATE: (available when CONNECT_result =1) & 0x3
# This field returns 00b if (LOOKING_4_CONNECTION=1)
SNK_CC1_Default             = 0x1   # (Above minimum vRd-Connect)
SNK_CC1_Power1_5            = 0x2   # (Above minimum vRd-Connect)
SNK_CC1_Power3_0            = 0x3   # (Above minimum vRd-Connect)

''' CC_HW_FAULT_STATUS_0 '''
VPU_VALID_TRANS             = 0x10
VPU_OVP_FAULT_TRANS         = 0x20

''' CC_HW_FAULT_STATUS_1 '''
VPU_OVP_FAULT               = 0x80  # 0: (NO_FAULT) No overvoltage condition 1: (FAULT) Overvoltage condition has occurred on CC
VPU_VALID                   = 0x40  # 0: (NO_VALID) CC pins pull-up voltage is below 1: (VALID) CC pins pull-up voltage is above UVLO threshold of 2.8 V
VBUS_DISCH_FAULT            = 0x10  # 0: (NO_FAULT) No VBUS discharge issue  1: (FAULT) VBUS discharge issue has occurred

''' PD_TYPEC_STATUS '''
PD_CLEAR                    = 0x00
PD_HARD_RESET_COMPLETE_ACK  = 0x08
PD_HARD_RESET_RECEIVED_ACK  = 0x0e
PD_HARD_RESET_SEND_ACK      = 0x0f

'''PRT_STATUS'''
PRL_HW_RST_RECEIVED         = 0x01
PRL_MSG_RECEIVED            = 0x04
PRL_BIST_RECEIVED           = 0x10

'''PORT_STATUS_1'''
# ATTACHED_DEVICE: ( >> 5 & 0x3)
NONE_ATT                    = 0x0
SNK_ATT                     = 0x1
DBG_ATT                     = 0x3

POWER_MODE                  = 0x8   # 0: device is sinking power 1 : reserved
DATA_MODE                   = 0x4   # 0: UFP, 1 reserved
ATTACH                      = 0x2   # 0: unattached, 1 : attached

'''  RDO_REG_STATUS_0 requested data object '''
RDO_MaxCurrent        = 0       # 10 Bits 9..0
RDO_OperatingCurrent  = 10      # 10 bits 19..10;
RDO_reserved_22_20    = 20      #
RDO_UnchunkedMess_sup = 23
RDO_UsbSuspend        = 24
RDO_UsbComCap         = 25
RDO_CapaMismatch      = 26
RDO_GiveBack          = 27
RDO_Object_Pos        = 28      # Bits 30..28 (3-bit)
RDO_reserved_31       = 31      # Bits 31

''' TYPEC_STATUS '''
REVERSE                     = 0x80  # 0: (STRAIGHT_CC1) CC1 is attached, 1: (TWISTED_CC2) CC2 is attached
# TYPEC_FSM_STATE: Indicates Type-C FSM state & 0x1f
UNATTACHED_SNK              = 0x0
ATTACHWAIT_SNK              = 0x1
ATTACHED_SNK                = 0x2
DEBUGACCESSORY_SNK          = 0x3
TRY_SRC                     = 0xc0
UNATTACHED_ACCESSORY        = 0xd0
ATTACHWAIT_ACCESSORY        = 0xe0
TYPEC_ERRORRECOVERY         = 0x13

""" MONITORING_CTRL_0  """
VBUS_SNK_DISC_THRESHOLD  = 0x8
MONITORING_INT_THRES_BYP = 0x4
EXT_VBUS_HIGH = 0x2
EXT_VBUS_LOW  = 0x1

''' PE_FSM '''
#PE_FSM_STATE: Policy engine layer FSM state
PE_INIT                     = 0x0
PE_SOFT_RESET               = 0x1
PE_HARD_RESET               = 0x2
PE_SEND_SOFT_RESET          = 0x3
PE_C_BIST                   = 0x4
PE_SNK_STARTUP              = 0x12
PE_SNK_DISCOVERY            = 0x13
PE_SNK_WAIT_FOR_CAPABILITIES= 0x14
PE_SNK_EVALUATE_CAPABILITIES= 0x15
PE_SNK_SELECT_CAPABILITIES  = 0x16
PE_SNK_TRANSITION_SINK      = 0x17
PE_SNK_READY                = 0x18
PE_SNK_READY_SENDING        = 0x19
PE_HARD_RESET_SHUTDOWN      = 0x1a
PE_HARD_RESET_RECOVERY      = 0x1b
PE_ERRORRECOVERY            = 0x40

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
            "ping": {
                'format': 'Ping: {{{data.address}}}'
            },
            "hi2c": {
                'format': '{{data.description}} {{data.action}} [ {{data.data}} ]'
            },
            "read": {
                'format': '{{data.description}}'
            },
            "resp": {
                'format': '{{data.description}} data[{{data.count}}]: [ {{data.data}} ]'
            }
    }

    temp_frame = None           # Working frame to build output
    register_type = None        # holds the register read or written
    data_byte = 0               # holds the most recent data read
    Maybe_reading = False       # True : Assume a register read request was send
    data_unknown = True         # True : No additional data received (indicating read request)
    request_register_type = None# Hold a register that has an assumed read requested pending
    snk_count = 0               # needed to decode the PDO/RDO info
    snk_data = 0                # needed to decode the PDO/RDO info

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        pass

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        # set our frame to an error frame, which will eventually get over-written as we get data.
        if self.temp_frame is None:
            self.temp_frame = AnalyzerFrame("hi2c", frame.start_time, frame.end_time, {
                    "address": "error",
                    "description" :"",
                    "data" : "",
                    "action" :"",
                    "count": 0
                }
            )

        if frame.type == "error":
            self.temp_frame.data["description"] = "error"

        if frame.type == "address":
            address_byte = frame.data["address"][0]
            self.temp_frame.data["address"] = hex(address_byte)

        if frame.type == "data":
            self.data_byte = frame.data["data"][0]

            # if waiting on responds from an assumed read request
            if self.Maybe_reading == True:
                # restore the saved register to (potentially) decode the responds
                self.register_type = self.request_register_type

            # no register known yet
            if self.register_type == None:
                self.register_type = hex(self.data_byte)

            # select decoder for register (if available)
            elif self.register_type == FTP_CUST_PASSWORD_REG:
                self.decode_passwd(self.data_byte)

            elif self.register_type == FTP_CTRL_0:
                self.decode_control0(self.data_byte)

            elif self.register_type == FTP_CTRL_1:
                self.decode_control1(self.data_byte)

            elif self.register_type == DPM_PDO_NUMB:
                self.decode_DPM_PDO_NUMB(self.data_byte)

            elif self.register_type == DPM_SNK_PDO1_0:
                self.decode_snk0(self.data_byte)

            elif self.register_type == DPM_SNK_PDO2_0:
                self.decode_snk0(self.data_byte)

            elif self.register_type == DPM_SNK_PDO3_0:
                self.decode_snk0(self.data_byte)

            elif self.register_type == PD_COMMAND_CTRL:
                self.decode_PD_COMMAND_CTRL(self.data_byte)

            elif self.register_type == TX_HEADER_LOW:
                self.decode_TX_HEADER_LOW(self.data_byte)

            elif self.register_type == ALERT_STATUS_1_MASK:
                self.decode_alert_mask(self.data_byte)

            elif self.register_type == ALERT_STATUS_1:
                self.decode_ALERT_STATUS_1(self.data_byte)

            elif self.register_type == TYPEC_MONITORING_STATUS_0:
                self.decode_TYPEC_MONITORING_STATUS_0(self.data_byte)

            elif self.register_type == TYPEC_MONITORING_STATUS_1:
                self.decode_TYPEC_MONITORING_STATUS_1(self.data_byte)

            elif self.register_type == CC_HW_FAULT_STATUS_0:
                self.decode_CC_HW_FAULT_STATUS_0(self.data_byte)

            elif self.register_type == CC_HW_FAULT_STATUS_1:
                self.decode_CC_HW_FAULT_STATUS_1(self.data_byte)

            elif self.register_type == CC_STATUS:
                self.decode_CC_STATUS(self.data_byte)

            elif self.register_type == PD_TYPEC_STATUS:
                self.decode_PD_TYPEC_STATUS(self.data_byte)

            elif self.register_type == PRT_STATUS:
                self.decode_PRT_STATUS(self.data_byte)

            elif self.register_type == MONITORING_CTRL_0:
                self.decode_MONITORING_CTRL_0(self.data_byte)

            elif self.register_type == MONITORING_CTRL_2:
                self.decode_MONITORING_CTRL_2(self.data_byte)

            elif self.register_type == RESET_CTRL:
                self.decode_RESET_CTRL(self.data_byte)

            elif self.register_type == VBUS_DISCHARGE_TIME_CTRL:
                self.decode_VBUS_DISCHARGE_TIME_CTRL(self.data_byte)

            elif self.register_type == VBUS_DISCHARGE_CTRL:
                self.decode_VBUS_DISCHARGE_CTRL(self.data_byte)

            elif self.register_type == GPIO_SW_GPIO:
                self.decode_GPIO_SW_GPIO(self.data_byte)

            elif self.register_type == PORT_STATUS_1:
                self.decode_PORT_STATUS_1(self.data_byte)

            elif self.register_type == TYPEC_STATUS:
                self.decode_TYPEC_STATUS(self.data_byte)

            elif self.register_type == VBUS_CTRL:
                self.decode_VBUS_CTRL(self.data_byte)

            elif self.register_type == PE_FSM:
                self.decode_PE_FSM(self.data_byte)

            elif self.register_type == RDO_REG_STATUS_0:
                self.decode_RDO_REG_STATUS_0(self.data_byte)


            # oh oh no decoder available for this register
            # either not created (yet) or not enough information to create decoder
            # for now supplying the raw data
            else:
                self.add_databyte()

        if frame.type == "stop":
            self.temp_frame.end_time = frame.end_time

            # if we had a read request before (single register) assume this is a responds on the read request
            if self.Maybe_reading == True:
                desc = self.temp_frame.data["description"]
                self.temp_frame.data["description"] = ""
                self.add_description("Responds:")
                self.add_description(desc)
                self.Maybe_reading = False

                new_frame = self.temp_frame

            # No data received in this frame
            elif self.data_unknown == True:

                # if only the address was received. assume a 'I2C-ping' to test the device is there
                if self.register_type == None:

                    new_frame = AnalyzerFrame("ping", self.temp_frame.start_time, frame.end_time, {
                    "address": self.temp_frame.data["address"],
                        }
                    )

                # if only ONE byte assume this is a register read request
                else:
                    self.add_description("Obtain ")
                    self.add_register(self.register_type)
                    self.request_register_type = self.register_type
                    self.Maybe_reading = True

                    new_frame = AnalyzerFrame("read", self.temp_frame.start_time, frame.end_time, {
                        "address": self.temp_frame.data["address"],
                        "description" : self.temp_frame.data["description"]
                        }
                )
            # this is a "normal" write to a register
            else:
                new_frame = self.temp_frame
                self.Maybe_reading = False

            # reset different variables
            self.data_unknown = True
            self.temp_frame = None
            self.register_type = None

            return new_frame

    def add_databyte(self):
        """ Just add data byte """
        self.temp_frame.data["count"] += 1
        if len(self.temp_frame.data["data"]) > 0:
            self.temp_frame.data["data"] += ", "
        self.temp_frame.data["data"] += hex(self.data_byte)
        self.temp_frame.data["description"] += "data only"

    def add_action(self,act):
        """ add comma separated action """
        if len(self.temp_frame.data["action"]) > 0:
            self.temp_frame.data["action"] += ", "
        self.temp_frame.data["action"] += act

    def add_description(self,act):
        """ add comma separated description """
        if len(self.temp_frame.data["description"]) > 0:
            self.temp_frame.data["description"] += ", "
        self.temp_frame.data["description"] += act
        self.data_unknown = False

    def add_register(self,act):
        """ Add a register to description """
        if act in STUSB_Registers:
            reg = STUSB_Registers[act]
            self.add_description(reg)
        else:
            self.add_description("unknown")

    def decode_RDO_REG_STATUS_0(self,data_byte):
        """ requested data object '''
        RDO_MaxCurrent        = 0       #  // 10 Bits 9..0
        RDO_OperatingCurrent  = 10      #  // 10 bits 19..10;
        RDO_reserved_22_20    = 20      #
        RDO_UnchunkedMess_sup = 23
        RDO_UsbSuspend        = 24
        RDO_UsbComCap         = 25
        RDO_CapaMismatch      = 26
        RDO_GiveBack          = 27
        RDO_Object_Pos        = 28      # Bits 30..28 (3-bit)
        RDO_reserved_31       = 31      # Bits 31
        """
        # get 4 data byte (MSB first)
        if self.snk_count < 4:
            tmp = data_byte
            tmp = (tmp << (8 * self.snk_count))
            self.snk_data = self.snk_data + tmp
            self.snk_count += 1

        if self.snk_count == 4:

            self.add_register(self.register_type)

            # bottom 10 bits is current
            current = (self.snk_data & 0x3ff) * 0.01

            # top 10 bits voltage
            voltage = ((self.snk_data >> RDO_OperatingCurrent) & 0x3ff) / 20

            self.temp_frame.data["description"] += "voltage: "
            self.temp_frame.data["description"] += str(voltage)
            self.temp_frame.data["description"] += ", current: "
            self.temp_frame.data["description"] += str(current)
            self.temp_frame.data["count"] += 4
            self.temp_frame.data["data"] += hex(self.snk_data)

            # 3 bits
            self.add_action(" Object_Pos: ")
            val = (self.snk_data >> RDO_Object_Pos) & 0x07
            self.temp_frame.data["action"] += str(val)
            #self.temp_frame.data["data"] += hex(val)

            self.add_action("UnchunkedMess_sup: ")
            val = (self.snk_data >> RDO_UnchunkedMess_sup) & 0x01
            self.temp_frame.data["action"] +=(str(val))

            self.add_action("UsbSuspend: ")
            val = (self.snk_data >> RDO_UsbSuspend) & 0x01
            self.temp_frame.data["action"] +=(str(val))

            self.add_action("UsbComCap: ")
            val = (self.snk_data >> RDO_UsbComCap) & 0x01
            self.temp_frame.data["action"] +=(str(val))

            self.add_action("CapaMismatch: ")
            val = (self.snk_data >> RDO_CapaMismatch) & 0x01
            self.temp_frame.data["action"] +=(str(val))

            self.add_action("GiveBack: ")
            val = (self.snk_data >> RDO_GiveBack) & 0x01
            self.temp_frame.data["action"] +=(str(val))

            self.snk_count = 0
            self.snk_data = 0

    def decode_control0(self, data_byte):
        """ decode control 0 register: NVM """
        self.add_register(self.register_type)

        if not data_byte & 0x40:
            self.add_action("Reset")

        if (data_byte >> FTP_CUST_PWR) & 0x01:
            self.add_action("FTP_CUST_PWR")

        if (data_byte >> FTP_CUST_RST_N) & 0x01:
            self.add_action("FTP_CUST_RST_N")

        if (data_byte >> FTP_CUST_REQ) & 0x01:
            self.add_action("FTP_CUST_REQ")

        sector = data_byte & 0x7

        if sector in Dec_control0_sect:
            sec = Dec_control0_sect[sector]
            self.add_action(sec)
        else:
            self.add_action("Sector?")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_control1(self, data_byte):
        """ decode control 1 register: NVM """
        self.add_register(self.register_type)

        opcode = data_byte & 0x7

        if opcode in Dec_control1_opcode:
            act = Dec_control1_opcode[opcode]
            self.add_action(act)
        else:
            self.add_action("Opcode?")

        sector = (data_byte >> 3) & 0x1f

        if sector in Dec_control1_sect:
            sec = Dec_control1_sect[sector]
            self.add_action(sec)
        else:
            self.add_action("Sector?")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_DPM_PDO_NUMB (self, data_byte):
        """ current PDO """
        self.add_register(self.register_type)
        self.temp_frame.data["data"] += hex(data_byte & 0x07)

    def decode_PE_FSM (self, data_byte):
        """
        read only
        #PE_FSM_STATE: Policy engine layer FSM state
        PE_INIT                         = 0x0
        PE_SOFT_RESET                   = 0x1
        PE_HARD_RESET                   = 0x2
        PE_SEND_SOFT_RESET              = 0x3
        PE_C_BIST                       = 0x4
        PE_SNK_STARTUP                  = 0x12
        PE_SNK_DISCOVERY                = 0x13
        PE_SNK_WAIT_FOR_CAPABILITIES    = 0x14
        PE_SNK_EVALUATE_CAPABILITIES    = 0x15
        PE_SNK_SELECT_CAPABILITIES      = 0x16
        PE_SNK_TRANSITION_SINK          = 0x17
        PE_SNK_READY                    = 0x18
        PE_SNK_READY_SENDING            = 0x19
        PE_HARD_RESET_SHUTDOWN          = 0x1a
        PE_HARD_RESET_RECOVERY          = 0x1b
        PE_ERRORRECOVERY                = 0x40
        """
        self.add_register(self.register_type)

        if data_byte == PE_INIT:
            self.add_description("PE_INIT")
        elif data_byte == PE_SOFT_RESET:
            self.add_description("PE_SOFT_RESET")
        elif data_byte == PE_HARD_RESET:
            self.add_description("PE_HARD_RESET")
        elif data_byte == PE_SEND_SOFT_RESET:
            self.add_description("PE_SEND_SOFT_RESET")
        elif data_byte == PE_C_BIST:
            self.add_description("PE_C_BIST")
        elif data_byte == PE_SNK_STARTUP:
            self.add_description("PE_SNK_STARTUP")
        elif data_byte == PE_SNK_DISCOVERY:
            self.add_description("PE_SNK_DISCOVERY")
        elif data_byte == PE_SNK_WAIT_FOR_CAPABILITIES:
            self.add_description("PE_SNK_WAIT_FOR_CAPABILITIES")
        elif data_byte == PE_SNK_EVALUATE_CAPABILITIES:
            self.add_description("PE_SNK_EVALUATE_CAPABILITIES")
        elif data_byte == PE_SNK_SELECT_CAPABILITIES:
            self.add_description("PE_SNK_SELECT_CAPABILITIES")
        elif data_byte == PE_SNK_TRANSITION_SINK:
            self.add_description("PE_SNK_TRANSITION_SINK")
        elif data_byte == PE_SNK_READY:
            self.add_description("PE_SNK_READY")
        elif data_byte == PE_SNK_READY_SENDING:
            self.add_description("PE_SNK_READY_SENDING")
        elif data_byte == PE_HARD_RESET_SHUTDOWN:
            self.add_description("PE_HARD_RESET_SHUTDOWN")
        elif data_byte == PE_ERRORRECOVERY:
            self.add_description("PE_ERRORRECOVERY")
        else:
            self.add_description("reserved")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_PD_COMMAND_CTRL(self, data_byte):

        self.add_register(self.register_type)

        if data_byte == 0x26:
            self.temp_frame.data["description"] += "Send command"
        else:
            self.temp_frame.data["description"] += "Unknown"

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_TX_HEADER_LOW(self, data_byte):

        self.add_register(self.register_type)

        if data_byte == 0x0D:
            self.temp_frame.data["description"] += "Soft Reset"
        else:
            self.temp_frame.data["description"] += "Unknown"

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_CC_HW_FAULT_STATUS_0(self, data_byte):
        """
        VPU_VALID_TRANS     = 0x10
        VPU_OVP_FAULT_TRANS = 0x20
        """
        self.add_register(self.register_type)

        if (data_byte & VPU_VALID_TRANS):
            self.add_action("VPU_VALID_TRANS")

        if (data_byte & VPU_OVP_FAULT_TRANS):
            self.add_action("VPU_OVP_FAULT_TRANS")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_CC_HW_FAULT_STATUS_1(self,data_byte):
        """
        read only

        VPU_OVP_FAULT               = 0x80  # 0: (NO_FAULT) No overvoltage condition 1: (FAULT) Overvoltage condition has occurred on CC
        VPU_VALID                   = 0x40  # 0: (NO_VALID) CC pins pull-up voltage is below 1: (VALID) CC pins pull-up voltage is above UVLO threshold of 2.8 V
        VBUS_DISCH_FAULT            = 0x10  # 0: (NO_FAULT) No VBUS discharge issue  1: (FAULT) VBUS discharge issue has occurred
        """

        self.add_register(self.register_type)

        if (data_byte & VPU_OVP_FAULT):
            self.add_action("(FAULT) Overvoltage")
        else:
            self.add_action("(NO_FAULT) No overvoltage")

        if (data_byte & VPU_VALID):
            self.add_action("(VALID) CC voltage")
        else:
            self.add_action("(NO_VALID) CC voltage")

        if (data_byte & VBUS_DISCH_FAULT):
            self.add_action("VBUS discharge issue")
        else:
            self.add_action("No VBUS discharge issue")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_MONITORING_CTRL_2(self, data_byte):

        self.add_register(self.register_type)

        lev = data_byte & 0xf
        self.add_action("OVP level")
        self.add_action(str(lev))

        lev = (data_byte >> 4) & 0xf
        self.add_action("UVP level")
        self.add_action(str(lev))

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_VBUS_DISCHARGE_TIME_CTRL(self, data_byte):

        self.add_register(self.register_type)

        lev = data_byte & 0xf
        self.temp_frame.data["action"] += "DISCHARGE_TIME_TRANSITION:"
        #self.add_action("DISCHARGE_TIME_TRANSITION:")
        self.add_action(str(lev))

        lev = (data_byte >> 4) & 0xf
        self.temp_frame.data["action"] += ", DISCHARGE_TIME_TO_0V:"
        #self.add_action("DISCHARGE_TIME_TO_0V:")
        self.add_action(str(lev))

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_passwd(self, data_byte):

        self.add_register(self.register_type)

        if hex(self.data_byte) == FTP_CUST_PASSWORD:
            self.add_action("set")
        else:
            self.add_action("clear")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_RESET_CTRL(self, data_byte):

        self.add_register(self.register_type)

        if data_byte & 0x01:
            self.add_action("Software reset enabled")
        else:
            self.add_action("Software reset disabled")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_VBUS_CTRL(self, data_byte):

        self.add_register(self.register_type)

        if data_byte & 0x02:
            self.add_action("Force the VBUS EN SNK pin")
        else:
            self.add_action("Disable VBUS_EN_SNK")

        self.temp_frame.data["data"] += hex(data_byte)


    def decode_VBUS_DISCHARGE_CTRL (self, data_byte):

        self.add_register(self.register_type)

        if data_byte & 0x80:
            self.add_action("VBUS_DISCHARGE: enabled")
        else:
            self.add_action("VBUS_DISCHARGE: disabled")

        if data_byte & 0x40:
            self.add_action("VSRC_DISCHARGE: enabled")
        else:
            self.add_action("VSRC_DISCHARGE: disabled")

        self.temp_frame.data["data"] += hex(data_byte)


    def decode_GPIO_SW_GPIO(self, data_byte):

        self.add_register(self.register_type)

        if data_byte & 0x01:
            self.add_action("SW_GPIO: enabled")
        else:
            self.add_action("SW_GPIO: disabled")

        self.temp_frame.data["data"] += hex(data_byte)


    def decode_MONITORING_CTRL_0(self, data_byte):
        """
        VBUS_SNK_DISC_THRESHOLD  = 0x8
        MONITORING_INT_THRES_BYP = 0x4
        EXT_VBUS_HIGH = 0x2
        EXT_VBUS_LOW  = 0x1

        """
        self.add_register(self.register_type)

        if data_byte & VBUS_SNK_DISC_THRESHOLD:
            self.add_action("VBUS threshold at 1.9 V")
        else:
            self.add_action("VBUS threshold at 3.5 V")

        if data_byte & MONITORING_INT_THRES_BYP:
            self.add_action("EXT_COMP")
        else:
            self.add_action("INT_COMP")

        if data_byte & EXT_VBUS_HIGH:
            self.add_action("HIGH_VBUS_ABOVE")
        else:
            self.add_action("HIGH_VBUS_VALID")

        if data_byte & EXT_VBUS_LOW:
            self.add_action("LOW_VBUS_BELOW")
        else:
            self.add_action("LOW_VBUS_VALID)")



        self.temp_frame.data["data"] += hex(data_byte)

    def decode_TYPEC_STATUS(self, data_byte):
        """
        read only

        REVERSE                 = 0x80  # 0: (STRAIGHT_CC1) CC1 is attached, 1: (TWISTED_CC2) CC2 is attached
        #TYPEC_FSM_STATE: Indicates Type-C FSM state & 0x1f
        UNATTACHED_SNK          = 0x0
        ATTACHWAIT_SNK          = 0x1
        ATTACHED_SNK            = 0x2
        DEBUGACCESSORY_SNK      = 0x3
        TRY_SRC                 = 0xc0
        UNATTACHED_ACCESSORY    = 0xd0
        ATTACHWAIT_ACCESSORY    = 0xe0
        TYPEC_ERRORRECOVERY     = 0x13
        """
        self.add_register(self.register_type)

        if data_byte & REVERSE:
            self.add_action("CC2 is attached")
        else:
            self.add_action("CC1 is attached")

        state = data_byte & 0x1f

        if state == UNATTACHED_SNK:
            self.add_action("UNATTACHED_SNK")

        elif state == ATTACHWAIT_SNK:
            self.add_action("ATTACHWAIT_SNK")

        elif state == ATTACHED_SNK:
            self.add_action("ATTACHED_SNK")

        elif state == DEBUGACCESSORY_SNK:
            self.add_action("DEBUGACCESSORY_SNK")

        elif state == TRY_SRC:
            self.add_action("TRY_SRC")

        elif state == UNATTACHED_ACCESSORY:
            self.add_action("UNATTACHED_ACCESSORY")

        elif state == ATTACHWAIT_ACCESSORY:
            self.add_action("ATTACHWAIT_ACCESSORY")

        elif state == TYPEC_ERRORRECOVERY:
            self.add_action("TYPEC_ERRORRECOVERY")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_PORT_STATUS_1(self, data_byte):
        """
        read only

        # ATTACHED_DEVICE: ( >> 5 & 0x3)
        NONE_ATT = 0x0
        SNK_ATT  = 0x1
        DBG_ATT  = 0x3

        POWER_MODE = 0x8   # 0: device is sinking power 1 : reserved
        DATA_MODE  = 0x4   # 0: UFP, 1 reserved
        ATTACH     = 0x2   # 0: unattached, 1 : attached
        """
        self.add_register(self.register_type)

        dev = data_byte >> 5

        if dev == NONE_ATT:
            self.add_action("NONE_ATT")

        elif dev == SNK_ATT:
            self.add_action("SNK_ATT")

        elif dev == DBG_ATT:
            self.add_action("DBG_ATT")

        if data_byte & POWER_MODE:
            self.add_action("Device sinking power")

        if data_byte & DATA_MODE:
            self.add_action("UFP")

        if data_byte & ATTACH:
            self.add_action("Attached")
        else:
            self.add_action("Unattached")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_PRT_STATUS(self,data_byte):
        """
        PRL_HW_RST_RECEIVED = 0x01
        PRL_MSG_RECEIVED    = 0x04
        PRL_BIST_RECEIVED   = 0x10
        """
        self.add_register(self.register_type)

        if data_byte & PRL_HW_RST_RECEIVED:
            self.add_action("PRL_HW_RST_RECEIVED")

        elif data_byte & PRL_MSG_RECEIVED:
            self.add_action("PRL_MSG_RECEIVED")

        elif data_byte & PRL_BIST_RECEIVED:
            self.add_action("PRL_BIST_RECEIVED")

        else:
            self.add_action("reserved")

        self.temp_frame.data["data"] += hex(data_byte)


    def decode_PD_TYPEC_STATUS(self,data_byte):
        """
        PD_CLEAR                    = 0x00
        PD_HARD_RESET_COMPLETE_ACK  = 0x08
        PD_HARD_RESET_RECEIVED_ACK  = 0x0e
        PD_HARD_RESET_SEND_ACK      = 0x0f
        """

        self.add_register(self.register_type)

        if data_byte == PD_CLEAR:
            self.add_action("PD_CLEAR")

        elif data_byte == PD_HARD_RESET_COMPLETE_ACK:
            self.add_action("PD_HARD_RESET_COMPLETE_ACK")

        elif data_byte == PD_HARD_RESET_RECEIVED_ACK:
            self.add_action("PD_HARD_RESET_RECEIVED_ACK")

        elif data_byte == PD_HARD_RESET_SEND_ACK:
            self.add_action("PD_HARD_RESET_SEND_ACK")

        else:
            self.add_action("reserved")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_CC_STATUS(self, data_byte):
        """
            LOOKING_4_CONNECTION        = 0x20  # 0: (NOT_LOOKING) 1: Looking
            CONNECT_RESULT              = 0x10  # 0: reserved  1: (PRESENT_RD) The device is presenting Rd.
            #CC2_STATE: (available when CONNECT_result =1) >> 2 & 0x3
            #This field returns 00b if (LOOKING_4_CONNECTION=1)
            SNK_CC2_Default             = 0x1   # (Above minimum vRd-Connect)
            SNK_CC2_Power1_5            = 0x2   # (Above minimum vRd-Connect)
            SNK_CC2_Power3_0            = 0x3   # (Above minimum vRd-Connect)
            #CC1_STATE: (available when CONNECT_result =1) & 0x3
            #This field returns 00b if (LOOKING_4_CONNECTION=1)
            SNK_CC1_Default             = 0x1   # (Above minimum vRd-Connect)
            SNK_CC1_Power1_5            = 0x2   # (Above minimum vRd-Connect)
            SNK_CC1_Power3_0            = 0x3   # (Above minimum vRd-Connect)
        """
        self.add_register(self.register_type)

        if (data_byte & LOOKING_4_CONNECTION):
            self.add_action("Try connecting")
        else:
            self.add_action("Not connecting")

        if (data_byte & CONNECT_RESULT):
            self.add_action("PRESENT_RD")

            cc2 = (data_byte >> 2) & 0x3
            if (cc2 == SNK_CC2_Default):
                self.add_action("SNK_CC2_Default")
            elif (cc2 == SNK_CC2_Power1_5):
                self.add_action("SNK_CC2_Power1_5")
            elif (cc2 == SNK_CC2_Power3_0):
                self.add_action("SNK_CC2_Power3_0")

            cc1 = data_byte & 0x3
            if (cc1 == SNK_CC1_Default):
                self.add_action("SNK_CC1_Default")
            elif (cc1 == SNK_CC1_Power1_5):
                self.add_action("SNK_CC1_Power1_5")
            elif (cc1 == SNK_CC1_Power3_0):
                self.add_action("SNK_CC1_Power3_0")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_TYPEC_MONITORING_STATUS_1(self, data_byte):
        """
        Read only

        TYPEC_MONITORING_STATUS_1
        VBUS_READY                  = 0x08  # 0: VBUS disconnected 1: VBUS connected
        VBUS_VSAFE0V                = 0x04  # 0: VBUS > 0.8V, 1: < 0.8V
        VBUS_VALID_SNK              = 0x02  # 0: VBUS < 1.9 V or 3.5 V  1: VBUS > 1.9 V or 3.5 V (depending of VBUS_SNK_DISC_THRESHOLD value)
        """
        self.add_register(self.register_type)

        if (data_byte & VBUS_READY):
            self.add_action("VBUS Connected")
        else:
            self.add_action("VBUS Disconnected")

        if (data_byte & VBUS_VSAFE0V):
            self.add_action("VBUS < 0.8V")
        else:
            self.add_action("VBUS > 0.8V")

        if (data_byte & VBUS_VALID_SNK):
            self.add_action("VBUS V > SNK_DISC_THRESHOLD")
        else:
            self.add_action("VBUS V < SNK_DISC_THRESHOLD")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_TYPEC_MONITORING_STATUS_0(self, data_byte):
        """
        VBUS_VALID_SNK_TRANS    = 0x02
        VBUS_VSAFE0V_TRANS      = 0x04
        VBUS_READY_TRANS        = 0x08
        VBUS_LOW_STATUS         = 0x10
        VBUS_HIGH_STATUS        = 0x20
        """
        self.add_register(self.register_type)

        if (data_byte & VBUS_VALID_SNK_TRANS):
            self.add_action("VBUS_VALID_SNK_TRANS")

        if (data_byte & VBUS_VSAFE0V_TRANS):
            self.add_action("VBUS_VSAFE0V_TRANS")

        if (data_byte & VBUS_READY_TRANS):
            self.add_action("VBUS_READY_TRANS")

        if (data_byte & VBUS_LOW_STATUS):
            self.add_action("VBUS_LOW_STATUS: ERR")
        else:
            self.add_action("VBUS_LOW_STATUS: OK")

        if (data_byte & VBUS_HIGH_STATUS):
            self.add_action("VBUS_HIGH_STATUS: ERR")
        else:
            self.add_action("VBUS_HIGH_STATUS: OK")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_ALERT_STATUS_1(self, data_byte):
        """
        Read only

        PRT_STATUS_AL              = 0x1
        CC_HW_FAULT_STATUS_AL      = 0x10
        TYPEC_MONITORING_STATUS_AL = 0x20
        PORT_STATUS_AL             = 0x40
        """

        self.add_register(self.register_type)

        if (data_byte & PRT_STATUS_AL):
            self.add_action("PRT_STATUS_AL")

        if (data_byte & CC_HW_FAULT_STATUS_AL):
            self.add_action("CC_HW_FAULT_STATUS_AL")

        if (data_byte & TYPEC_MONITORING_STATUS_AL):
            self.add_action("TYPEC_MONITORING_STATUS_AL")

        if (data_byte & PORT_STATUS_AL):
            self.add_action("PORT_STATUS_AL")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_alert_mask(self, data_byte):
        """
        PRT_STATUS_AL = 0x1
        CC_HW_FAULT_STATUS_AL = 0x10
        TYPEC_MONITORING_STATUS_AL = 0x20
        PORT_STATUS_AL= 0x40
        """
        self.add_register(self.register_type)

        if (data_byte & PRT_STATUS_AL):
            self.add_action("PRT_STATUS_AL: MASKED")
        else:
            self.add_action("PRT_STATUS_AL: UNMASKED")

        if (data_byte & CC_HW_FAULT_STATUS_AL):
            self.add_action("CC_HW_FAULT_STATUS_AL: MASKED")
        else:
            self.add_action("CC_HW_FAULT_STATUS_AL: UNMASKED")

        if (data_byte & TYPEC_MONITORING_STATUS_AL):
            self.add_action("TYPEC_MONITORING_STATUS_AL: MASKED")
        else:
            self.add_action("TYPEC_MONITORING_STATUS_AL: UNMASKED")

        if (data_byte & PORT_STATUS_AL):
            self.add_action("PORT_STATUS_AL: MASKED")
        else:
            self.add_action("PORT_STATUS_AL: UNMASKED")

        self.temp_frame.data["data"] += hex(data_byte)

    def decode_snk0(self, data_byte):
        """decode sink PDO """

        # get 4 data byte (MSB first)
        if self.snk_count < 4:
            tmp = data_byte
            tmp = (tmp << (8 * self.snk_count))
            self.snk_data = self.snk_data + tmp
            self.snk_count += 1

        if self.snk_count == 4:

            self.add_register(self.register_type)

            # bottom 10 bits is current
            current = (self.snk_data & 0x3ff) * 0.01

            # top 10 bits voltage
            voltage = ((self.snk_data >> 10) & 0x3ff) / 20

            self.temp_frame.data["description"] += "voltage: "
            self.temp_frame.data["description"] += str(voltage)
            self.temp_frame.data["description"] += ", current: "
            self.temp_frame.data["description"] += str(current)
            self.temp_frame.data["count"] += 4
            self.temp_frame.data["data"] += hex(self.snk_data)

            self.snk_count = 0
            self.snk_data = 0

