# -*- coding: utf-8 -*-

## Make Serial command

import sys
import re
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

OP_SEARCHALL = 1
OP_GETCOMMAND = 2
OP_SETCOMMAND = 3
OP_SETFILE = 4
OP_GETFILE = 5
OP_FWUP = 6

# Supported devices
ONE_PORT_DEV = [
    "WIZ750SR",
    # "WIZ750SR-100",
    # "WIZ750SR-105",
    # "WIZ750SR-110",
    # "WIZ107SR",
    # "WIZ108SR",
    "ASG200", 
    "ASG210"
]
TWO_PORT_DEV = ["WIZ752SR-12x", "WIZ752SR-120", "WIZ752SR-125"]
ASG_DEV = ["ASG200", "ASG210"]

# ASG2X0 config
# cmd_asg = ["MC", "VR", "MN", "IM", "OP", "LI", "SM", "GW", "DS", "WF", "WS", "WP"]
cmd_asg = ["MC", "VR", "MN", "IM", "OP", "LI", "SM", "GW", "DS"]


def version_compare(version1, version2):
    def normalize(v):
        # return [x for x in re.sub(r'(\.0+)*$','',v).split('.')]
        return [x for x in re.sub(r"(\.0+\.[dev])*$", "", v).split(".")]

    obj1 = normalize(version1)
    obj2 = normalize(version2)
    return (obj1 > obj2) - (obj1 < obj2)
    # if return value < 0: version2 upper than version1


class WIZMakeCMD:
    def __init__(self):
        pass

    def make_header(self, mac_addr, idcode, devname='', set_pw=''):
        cmd_header = []
        cmd_header.append(["MA", mac_addr])
        cmd_header.append(["PW", idcode])
        # print('reset', mac_addr, idcode, set_pw, devname)

        return cmd_header

    def presearch(self, mac_addr, idcode):
        cmd_list = self.make_header(mac_addr, idcode)
        # Search All Devices on the network
        # 장치 검색 시 필요 정보 Get
        for cmd in cmd_asg:
            cmd_list.append([cmd, ""])
        return cmd_list

    # Set device
    # TODO: device profile 적용
    def setcommand(self, mac_addr, idcode, set_pw, command_list, param_list, devname, version):
        cmd_list = self.make_header(mac_addr, idcode, devname=devname, set_pw=set_pw)
        try:
            # print('Macaddr: %s' % mac_addr)

            for i in range(len(command_list)):
                cmd_list.append([command_list[i], param_list[i]])
            
            if devname in ONE_PORT_DEV:
                for cmd in cmd_asg:
                    cmd_list.append([cmd, ""])
            cmd_list.append(["SV", ""])  # save device setting
            cmd_list.append(["RT", ""])  # Device reboot
            # print("setcommand()", cmd_list)
            return cmd_list
        except Exception as e:
            sys.stdout.write("[ERROR] setcommand(): %r\r\n" % e)

    def reset(self, mac_addr, idcode, set_pw, devname):
        print('reset', mac_addr, idcode, set_pw, devname)
        cmd_list = self.make_header(mac_addr, idcode, devname=devname, set_pw=set_pw)
        cmd_list.append(["RT", ""])
        return cmd_list

    def factory_reset(self, mac_addr, idcode, set_pw, devname, param):
        cmd_list = self.make_header(mac_addr, idcode, devname=devname, set_pw=set_pw)
        cmd_list.append(["FR", param])
        return cmd_list
