# -*- coding: utf-8 -*-

from WIZMakeCMD import WIZMakeCMD, ONE_PORT_DEV
from WIZ750CMDSET import WIZ750CMDSET
from WIZUDPSock import WIZUDPSock
from WIZMSGHandler import WIZMSGHandler
import sys
import os

# need to install package
from PyQt5 import QtWidgets, QtCore, QtGui, uic
import ifaddr

import logging
import logging.handlers

testlog = logging.getLogger("testlogging")
testlog.setLevel(logging.INFO)

fileformatter = logging.Formatter("[%(levelname)s][%(asctime)s]-(%(funcName)s)(%(lineno)s) %(message)s")

fileHandler = logging.FileHandler("./toollogging.log", encoding="utf-8")
streamHandler = logging.StreamHandler()

fileHandler.setFormatter(fileformatter)
streamHandler.setFormatter(fileformatter)

# log handler
testlog.addHandler(fileHandler)
testlog.addHandler(streamHandler)

OP_SEARCHALL = 1
OP_SETCOMMAND = 3

SOCK_CLOSE_STATE = 1
SOCK_OPENTRY_STATE = 2
SOCK_OPEN_STATE = 3
SOCK_CONNECTTRY_STATE = 4
SOCK_CONNECT_STATE = 5

VERSION = "V0.9.2 beta"


def resource_path(relative_path):
    # Get absolute path to resource, works for dev and for PyInstaller
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


# Load ui files
main_window = uic.loadUiType(resource_path("gui/wizconfig_gui.ui"))[0]


class WIZWindow(QtWidgets.QMainWindow, main_window):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.setWindowTitle("WIZnet ASG2X0 Series Configuration Tool " + VERSION)

        self.logging = testlog

        # GUI font size init
        self.midfont = None
        self.smallfont = None
        self.btnfont = None

        # Tool operation mode
        self.mode_asgconfig = True

        self.gui_init()

        # Main icon
        self.setWindowIcon(QtGui.QIcon(resource_path("gui/icon.ico")))
        self.set_btn_icon()

        self.wiz750cmdObj = WIZ750CMDSET(1)
        self.wizmakecmd = WIZMakeCMD()

        self.dev_profile = {}
        self.searched_devnum = None
        # init search option
        self.retry_search_num = 1
        self.search_wait_time = 3

        self.encoded_setting_pw = ""

        self.mac_list = []
        self.dev_name = []
        self.vr_list = []
        self.threads = []
        self.curr_mac = None
        self.curr_dev = None
        self.curr_ver = None
        self.code = " "
        self.eachdev_info = []

        self.search_pre_wait_time = 3
        self.search_wait_time_each = 1
        self.search_retry_flag = False
        self.search_retrynum = 0

        self.saved_path = None
        self.selected_eth = None
        self.cli_sock = None

        self.isConnected = False
        self.set_reponse = None
        self.wizmsghandler = None

        # Initial factory reset toolbutton
        self.init_btn_factory()

        # device select event
        self.list_device.itemClicked.connect(self.dev_clicked)

        # Button event
        self.btn_search.clicked.connect(self.do_search_normal)

        self.btn_setting.clicked.connect(self.event_setting_clicked)
        self.btn_reset.clicked.connect(self.event_reset_clicked)

        # factory reset
        self.btn_factory.clicked.connect(self.event_factory_setting)

        # configuration save/load button
        self.btn_exit.clicked.connect(self.msg_exit)

        # State Changed Event
        self.ip_dhcp.clicked.connect(self.event_ip_alloc)
        self.ip_static.clicked.connect(self.event_ip_alloc)

        # Event: OP mode
        self.ch1_tcpclient.clicked.connect(self.event_opmode)
        self.ch1_tcpserver.clicked.connect(self.event_opmode)
        self.ch1_tcpmixed.clicked.connect(self.event_opmode)
        self.ch1_udp.clicked.connect(self.event_opmode)

        self.pgbar = QtWidgets.QProgressBar()
        self.statusbar.addPermanentWidget(self.pgbar)

        # progress thread
        self.th_search = ThreadProgress()
        self.th_search.change_value.connect(self.value_changed)

        # check if device selected
        self.list_device.itemSelectionChanged.connect(self.dev_selected)

        # Menu event - File
        self.actionExit.triggered.connect(self.msg_exit)

        # Menu event - Help
        self.about_wiz.triggered.connect(self.about_info)

        # Menu event - Option
        self.net_adapter_info()
        self.netconfig_menu.triggered[QtWidgets.QAction].connect(self.net_ifs_selected)
        # Menu event - Option - Search option
        self.action_set_wait_time.triggered.connect(self.input_search_wait_time)
        self.action_retry_search.triggered.connect(self.input_retry_search)

        # network interface selection
        self.net_interface.currentIndexChanged.connect(self.net_changed)

        # Tab changed
        self.generalTab.currentChanged.connect(self.tab_changed)

    def init_btn_factory(self):
        # factory_option = ['Factory default settings', 'Factory default firmware']
        self.factory_setting_action = QtWidgets.QAction("Factory default settings", self)
        self.factory_firmware_action = QtWidgets.QAction("Factory default firmware", self)

        self.btn_factory.addAction(self.factory_setting_action)
        self.btn_factory.addAction(self.factory_firmware_action)

    def tab_changed(self):
        pass

    def net_ifs_selected(self, netifs):
        ifs = netifs.text().split(":")
        selected_ip = ifs[0]
        selected_name = ifs[1]

        self.logging.info("net_ifs_selected() %s: %s" % (selected_ip, selected_name))

        self.statusbar.showMessage(" Selected: %s: %s" % (selected_ip, selected_name))
        self.selected_eth = selected_ip

    def value_changed(self, value):
        self.pgbar.show()
        self.pgbar.setValue(value)

    def dev_selected(self):
        if len(self.list_device.selectedItems()) == 0:
            self.disable_object()
        else:
            self.object_config()

    def net_changed(self, ifs):
        self.logging.info(self.net_interface.currentText())
        ifs = self.net_interface.currentText().split(":")
        selected_ip = ifs[0]
        selected_name = ifs[1]

        self.statusbar.showMessage(" Selected eth: %s: %s" % (selected_ip, selected_name))
        self.selected_eth = selected_ip

    # Get network adapter & IP list
    def net_adapter_info(self):
        self.netconfig_menu = QtWidgets.QMenu("Network Interface Config", self)
        self.netconfig_menu.setFont(self.midfont)
        self.menuOption.addMenu(self.netconfig_menu)

        adapters = ifaddr.get_adapters()
        self.net_list = []

        for adapter in adapters:
            # print("Net Interface:", adapter.nice_name)
            for ip in adapter.ips:
                if len(ip.ip) > 6:
                    ipv4_addr = ip.ip
                    if ipv4_addr == "127.0.0.1":
                        pass
                    else:
                        net_ifs = ipv4_addr + ":" + adapter.nice_name

                        # -- get network interface list
                        self.net_list.append(adapter.nice_name)
                        netconfig = QtWidgets.QAction(net_ifs, self)
                        self.netconfig_menu.addAction(netconfig)
                        self.net_interface.addItem(net_ifs)
                # else:
                #     ipv6_addr = ip.ip

    def disable_object(self):
        self.btn_reset.setEnabled(False)
        self.btn_factory.setEnabled(False)
        self.btn_setting.setEnabled(False)

        self.generalTab.setEnabled(False)
        self.channel_tab.setEnabled(False)

    def object_config(self):
        self.selected_devinfo()

        # Enable buttons
        # self.btn_reset.setEnabled(True)
        # self.btn_factory.setEnabled(True)
        self.btn_setting.setEnabled(True)

        # Enable tab group
        self.generalTab.setEnabled(True)
        self.generalTab.setTabEnabled(0, True)

        # Enable channel tab
        self.channel_tab.setEnabled(True)
        self.channel_tab_config()

        self.event_ip_alloc()
        self.event_opmode()

        # temp
        self.groupbox_wifi.setDisabled(True)

    def channel_tab_config(self):
        # channel tab config
        if self.curr_dev in ONE_PORT_DEV or "ASG" in self.curr_dev:
            # self.channel_tab.removeTab(1)
            self.channel_tab.setTabEnabled(0, True)

    # button click events
    def event_setting_clicked(self):
        self.do_setting()

    def event_reset_clicked(self):
        self.do_reset()

    def event_factory_setting(self):
        self.msg_factory_setting()

    # factory reset options
    # option: factory button / menu 1, menu 2
    def event_factory_option_clicked(self, option):
        self.logging.info(option.text())
        opt = option.text()

        if "settings" in opt:
            self.event_factory_setting()
        elif "firmware" in opt:
            self.event_factory_firmware()

    def event_ip_alloc(self):
        if self.ip_dhcp.isChecked() is True:
            self.localip.setEnabled(False)
            self.subnet.setEnabled(False)
            self.gateway.setEnabled(False)
            self.dns_addr.setEnabled(False)
        elif self.ip_dhcp.isChecked() is False:
            self.localip.setEnabled(True)
            self.subnet.setEnabled(True)
            self.gateway.setEnabled(True)
            self.dns_addr.setEnabled(True)

    def event_opmode(self):
        if self.ch1_tcpclient.isChecked() is True:
            self.ch1_remote.setEnabled(True)
        elif self.ch1_tcpserver.isChecked() is True:
            self.ch1_remote.setEnabled(False)
        elif self.ch1_tcpmixed.isChecked() is True:
            self.ch1_remote.setEnabled(True)
        elif self.ch1_udp.isChecked() is True:
            self.ch1_remote.setEnabled(True)

    def sock_close(self):
        # 기존 연결 fin
        if self.cli_sock is not None:
            if self.cli_sock.state != SOCK_CLOSE_STATE:
                self.cli_sock.shutdown()

    def socket_config(self):
        # Broadcast
        if self.selected_eth is None:
            self.conf_sock = WIZUDPSock(5000, 52000, "")
        else:
            self.conf_sock = WIZUDPSock(5000, 52000, self.selected_eth)
            self.logging.info(self.selected_eth)

        self.conf_sock.open()

    def do_search_retry(self, num):
        self.search_retry_flag = True
        # search retry number
        self.search_retrynum = num
        self.logging.info(self.mac_list)

        self.search_pre()

    def do_search_normal(self):
        self.search_retry_flag = False
        self.search_pre()

    def search_pre(self):
        if self.wizmsghandler is not None and self.wizmsghandler.isRunning():
            self.wizmsghandler.wait()
            # print('wait')
        else:
            # 기존 연결 close
            self.sock_close()

            cmd_list = []
            # default search id code
            self.code = " "
            self.all_response = []
            self.pgbar.setFormat("Searching..")
            self.pgbar.setRange(0, 100)
            self.th_search.start()
            self.processing()

            if self.search_retry_flag:
                self.logging.info("keep searched list")
                pass
            else:
                # List table initial (clear)
                self.list_device.clear()
                while self.list_device.rowCount() > 0:
                    self.list_device.removeRow(0)

            item_mac = QtWidgets.QTableWidgetItem()
            item_mac.setText("Mac address")
            item_mac.setFont(self.midfont)
            self.list_device.setHorizontalHeaderItem(0, item_mac)

            item_name = QtWidgets.QTableWidgetItem()
            item_name.setText("Name")
            item_name.setFont(self.midfont)
            self.list_device.setHorizontalHeaderItem(1, item_name)

            self.socket_config()
            # self.logging.info('search: conf_sock: %s' % self.conf_sock)

            # Search devices
            self.statusbar.showMessage(" Searching devices...")

            cmd_list = self.wizmakecmd.presearch("FF:FF:FF:FF:FF:FF", self.code)
            # self.logging.info(cmd_list)

            self.wizmsghandler = WIZMSGHandler(
                self.conf_sock, cmd_list, "udp", OP_SEARCHALL, self.search_pre_wait_time
            )

            self.wizmsghandler.search_result.connect(self.get_search_result)
            self.wizmsghandler.searched_data.connect(self.getsearch_each_dev)
            self.wizmsghandler.start()

    def processing(self):
        self.btn_search.setEnabled(False)
        # QtCore.QTimer.singleShot(1500, lambda: self.btn_search.setEnabled(True))
        QtCore.QTimer.singleShot(4500, lambda: self.pgbar.hide())

    def search_each_dev(self, dev_info_list):
        cmd_list = []
        self.eachdev_info = []
        self.pgbar.setFormat("Search for each device...")

        self.socket_config()

        # Search devices
        self.statusbar.showMessage(" Get each device information...")

        # dev_info => [mac_addr, name, version]
        for dev_info in dev_info_list:
            # self.logging.info(dev_info)
            cmd_list = self.wizmakecmd.search(dev_info[0], self.code, dev_info[1], dev_info[2])
            # print(cmd_list)
            th_name = "dev_%s" % dev_info[0]
            th_name = WIZMSGHandler(self.conf_sock, cmd_list, "udp", OP_SEARCHALL, self.search_wait_time_each)
            th_name.searched_data.connect(self.getsearch_each_dev)
            th_name.start()
            th_name.wait()
            self.statusbar.showMessage(" Done.")

    def getsearch_each_dev(self, dev_data):
        # self.logging.info(dev_data)
        profile = {}

        try:
            if dev_data != b"":
                self.eachdev_info.append(dev_data)
                # print('eachdev_info', len(self.eachdev_info), self.eachdev_info)
                for i in range(len(self.eachdev_info)):
                    # cmdsets = self.eachdev_info[i].splitlines()
                    cmdsets = self.eachdev_info[i].split(b"\r\n")

                    for i in range(len(cmdsets)):
                        # print('cmdsets', i, cmdsets[i], cmdsets[i][:2], cmdsets[i][2:])
                        if cmdsets[i][:2] == b"MA":
                            pass
                        else:
                            cmd = cmdsets[i][:2].decode()
                            param = cmdsets[i][2:].decode()
                            profile[cmd] = param

                    # self.logging.info(profile)
                    self.dev_profile[profile["MC"]] = profile
                    profile = {}

                    self.all_response = self.eachdev_info

                    # when retry search
                    if self.search_retrynum:
                        self.logging.info(self.search_retrynum)
                        self.search_retrynum = self.search_retrynum - 1
                        self.search_pre()
                    else:
                        pass
            else:
                pass
        except Exception as e:
            self.logging.error(e)
            self.msg_error("[ERROR] getsearch_each_dev(): {}".format(e))

        # print('self.dev_profile', self.dev_profile)

    def get_search_result(self, devnum):
        if self.search_retry_flag:
            pass
        else:
            # init old info
            self.mac_list = []
            self.dev_name = []
            self.vr_list = []

        if self.wizmsghandler.isRunning():
            self.wizmsghandler.wait()
        if devnum >= 0:
            self.searched_devnum = devnum
            # self.logging.info(self.searched_devnum)
            self.btn_search.setEnabled(True)

            if devnum == 0:
                self.logging.info("No device.")
            else:
                if self.search_retry_flag:
                    self.logging.info("search retry flag on")
                    new_mac_list = self.wizmsghandler.mac_list
                    new_mn_list = self.wizmsghandler.mn_list
                    new_vr_list = self.wizmsghandler.vr_list
                    new_resp_list = self.wizmsghandler.rcv_list

                    # check mac list
                    for i in range(len(new_mac_list)):
                        if new_mac_list[i] in self.mac_list:
                            pass
                        else:
                            self.mac_list.append(new_mac_list[i])
                            self.dev_name.append(new_mn_list[i])
                            self.vr_list.append(new_vr_list[i])
                            self.all_response.append(new_resp_list[i])
                else:
                    self.mac_list = self.wizmsghandler.mac_list
                    self.dev_name = self.wizmsghandler.mn_list
                    self.vr_list = self.wizmsghandler.vr_list
                    # all response
                    self.all_response = self.wizmsghandler.rcv_list

                # print('all_response', len(self.all_response), self.all_response)

                # row length = the number of searched devices
                self.list_device.setRowCount(len(self.mac_list))

                try:
                    for i in range(0, len(self.mac_list)):
                        # device = "%s | %s" % (self.mac_list[i].decode(), self.dev_name[i].decode())
                        self.list_device.setItem(i, 0, QtWidgets.QTableWidgetItem(self.mac_list[i].decode()))
                        self.list_device.setItem(i, 1, QtWidgets.QTableWidgetItem(self.dev_name[i].decode()))
                except Exception as e:
                    self.logging.error(e)

                # resize for data
                self.list_device.resizeColumnsToContents()
                self.list_device.resizeRowsToContents()

                # row/column resize disable
                self.list_device.horizontalHeader().setSectionResizeMode(2)
                self.list_device.verticalHeader().setSectionResizeMode(2)

            self.statusbar.showMessage(" Find %d devices" % devnum)
            self.get_dev_list()
        else:
            self.logging.info("search error")

    def get_dev_list(self):
        # basic_data = None
        self.searched_dev = []
        self.dev_data = {}

        print(self.mac_list, self.dev_name, self.vr_list)
        if self.mac_list is not None:
            try:
                for i in range(len(self.mac_list)):
                    self.searched_dev.append(
                        [self.mac_list[i].decode(), self.dev_name[i].decode(), self.vr_list[i].decode()]
                    )
                    self.dev_data[self.mac_list[i].decode()] = [self.dev_name[i].decode(), self.vr_list[i].decode()]
            except Exception as e:
                self.logging.error(e)

            # print('get_dev_list()', self.searched_dev, self.dev_data)

            # ! not use each search
            # self.search_each_dev(self.searched_dev)
        else:
            self.logging.info("There is no device.")

    def dev_clicked(self):
        for currentItem in self.list_device.selectedItems():
            # print('Click info:', currentItem, currentItem.row(), currentItem.column(), currentItem.text())
            # print('clicked', self.list_device.selectedItems()[0].text())
            # self.getdevinfo(currentItem.row())
            clicked_mac = self.list_device.selectedItems()[0].text()

        self.get_clicked_devinfo(clicked_mac)

    def get_clicked_devinfo(self, macaddr):
        self.object_config()

        # device profile(json format)
        if macaddr in self.dev_profile:
            dev_data = self.dev_profile[macaddr]
            # print('clicked device information:', dev_data)

            self.fill_devinfo(dev_data)
        else:
            if len(self.dev_profile) != self.searched_devnum:
                self.logging.info("warning: 검색된 장치의 수와 프로파일된 장치의 수가 다릅니다.")
            self.logging.info("warning: retry search")

    # TODO: decode exception handling
    def fill_devinfo(self, dev_data):
        # print("fill_devinfo", dev_data)
        try:
            # device info (RO)
            if "MN" in dev_data:
                self.dev_type.setText(dev_data["MN"])
            if "VR" in dev_data:
                self.fw_version.setText(dev_data["VR"])
            # device info - channel 1
            if "ST" in dev_data:
                self.ch1_status.setText(dev_data["ST"])
            # if "UN" in dev_data:
            #     self.ch1_uart_name.setText(dev_data["UN"])
            # Network - general
            if "IM" in dev_data:
                if dev_data["IM"] == "0":
                    self.ip_static.setChecked(True)
                elif dev_data["IM"] == "1":
                    self.ip_dhcp.setChecked(True)
            if "LI" in dev_data:
                self.localip.setText(dev_data["LI"])
                self.localip_addr = dev_data["LI"]
            if "SM" in dev_data:
                self.subnet.setText(dev_data["SM"])
            if "GW" in dev_data:
                self.gateway.setText(dev_data["GW"])
            if "DS" in dev_data:
                self.dns_addr.setText(dev_data["DS"])

            # Network - channel 1
            if "OP" in dev_data:
                if dev_data["OP"] == "0":
                    self.ch1_tcpclient.setChecked(True)
                elif dev_data["OP"] == "1":
                    self.ch1_tcpserver.setChecked(True)
                elif dev_data["OP"] == "2":
                    self.ch1_tcpmixed.setChecked(True)
                elif dev_data["OP"] == "3":
                    self.ch1_udp.setChecked(True)

            if "LP" in dev_data:
                self.ch1_localport.setText(dev_data["LP"])
            if "RH" in dev_data:
                self.ch1_remoteip.setText(dev_data["RH"])
            if "RP" in dev_data:
                self.ch1_remoteport.setText(dev_data["RP"])

            # WiFi Configuration

            self.object_config()
        except Exception as e:
            self.logging.error(e)
            self.msg_error("Get device information error {}".format(e))

    def msg_error(self, error):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Critical)
        msgbox.setFont(self.midfont)
        msgbox.setWindowTitle("Unexcepted error")
        text = (
            "<div style=text-align:center>Unexcepted error occurred."
            + "<br>Please report the issue with detail message."
            + "<br><a href='https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/issues'>Github Issue page</a></div>"
        )
        msgbox.setText(text)
        # detail info
        msgbox.setDetailedText(str(error))
        msgbox.exec_()

    def getinfo_for_setting(self, row_index):
        self.rcv_data[row_index] = self.set_reponse[0]
        # print('getinfo_for_setting set_response', self.set_reponse)

    # get each object's value for setting
    def get_object_value(self):
        self.selected_devinfo()

        setcmd = {}

        try:
            # Network - general
            setcmd["LI"] = self.localip.text()
            setcmd["SM"] = self.subnet.text()
            setcmd["GW"] = self.gateway.text()
            if self.ip_static.isChecked() is True:
                setcmd["IM"] = "0"
            elif self.ip_dhcp.isChecked() is True:
                setcmd["IM"] = "1"
            setcmd["DS"] = self.dns_addr.text()

            # Network - channel 1
            if self.ch1_tcpclient.isChecked() is True:
                setcmd["OP"] = "0"
            elif self.ch1_tcpserver.isChecked() is True:
                setcmd["OP"] = "1"
            elif self.ch1_tcpmixed.isChecked() is True:
                setcmd["OP"] = "2"
            elif self.ch1_udp.isChecked() is True:
                setcmd["OP"] = "3"
            setcmd["LP"] = self.ch1_localport.text()
            setcmd["RH"] = self.ch1_remoteip.text()
            setcmd["RP"] = self.ch1_remoteport.text()
        except Exception as e:
            self.logging.error(e)

        # print('setcmd:', setcmd)
        return setcmd

    def do_setting(self):
        self.disable_object()

        self.set_reponse = None

        self.sock_close()

        if len(self.list_device.selectedItems()) == 0:
            # self.logging.info('Device is not selected')
            self.msg_dev_not_selected()
        else:
            self.statusbar.showMessage(" Setting device...")
            # matching set command
            setcmd = self.get_object_value()
            # self.selected_devinfo()

            if self.curr_dev in ONE_PORT_DEV or "WIZ750" in self.curr_dev:
                self.logging.info("One port dev setting")
                # Parameter validity check
                invalid_flag = 0
                setcmd_cmd = list(setcmd.keys())
                for i in range(len(setcmd)):
                    if self.wiz750cmdObj.isvalidparameter(setcmd_cmd[i], setcmd.get(setcmd_cmd[i])) is False:
                        self.logging.info("Invalid parameter: %s %s" % (setcmd_cmd[i], setcmd.get(setcmd_cmd[i])))
                        self.msg_invalid(setcmd.get(setcmd_cmd[i]))
                        invalid_flag += 1
            else:
                invalid_flag = -1
                self.logging.info("The device is not supported")

            # self.logging.info('invalid flag: %d' % invalid_flag)
            if invalid_flag > 0:
                pass
            elif invalid_flag == 0:
                cmd_list = self.wizmakecmd.setcommand(
                    self.curr_mac,
                    self.code,
                    self.encoded_setting_pw,
                    list(setcmd.keys()),
                    list(setcmd.values()),
                    self.curr_dev,
                    self.curr_ver,
                )
                # self.logging.info(cmd_list)

                # socket config
                self.socket_config()

                self.wizmsghandler = WIZMSGHandler(self.conf_sock, cmd_list, "udp", OP_SETCOMMAND, 2)
                self.wizmsghandler.set_result.connect(self.get_setting_result)
                self.wizmsghandler.start()

    def get_setting_result(self, resp_len):
        set_result = {}

        if resp_len > 100:
            self.statusbar.showMessage(" Set device complete!")

            # complete pop-up
            self.msg_set_success()

            # get setting result
            self.set_reponse = self.wizmsghandler.rcv_list[0]

            # cmdsets = self.set_reponse.splitlines()
            cmdsets = self.set_reponse.split(b"\r\n")

            for i in range(len(cmdsets)):
                if cmdsets[i][:2] == b"MA":
                    pass
                else:
                    try:
                        cmd = cmdsets[i][:2].decode()
                        param = cmdsets[i][2:].decode()
                    except Exception as e:
                        self.logging.error(e)
                    set_result[cmd] = param

            try:
                clicked_mac = self.list_device.selectedItems()[0].text()
                self.dev_profile[clicked_mac] = set_result

                self.fill_devinfo(clicked_mac)
            except Exception as e:
                self.logging.error(e)

            self.dev_clicked()
        elif resp_len == -1:
            self.logging.info("Setting: no response from device.")
            self.statusbar.showMessage(" Setting: no response from device.")
            self.msg_set_error()
        elif resp_len < 50:
            self.logging.info("Warning: setting is did not well.")
            self.statusbar.showMessage(" Warning: setting is did not well.")
            self.msg_set_warning()

        self.object_config()

    def selected_devinfo(self):
        # 선택된 장치 정보 get
        for currentItem in self.list_device.selectedItems():
            if currentItem.column() == 0:
                self.curr_mac = currentItem.text()
                self.curr_ver = self.dev_data[self.curr_mac][1]
                # print('current device:', self.curr_mac, self.curr_ver)
            elif currentItem.column() == 1:
                self.curr_dev = currentItem.text()
                # print('current dev name:', self.curr_dev)
            self.statusbar.showMessage(" Current device [%s : %s], %s" % (self.curr_mac, self.curr_dev, self.curr_ver))

    def reset_result(self, resp_len):
        if resp_len > 0:
            self.statusbar.showMessage(" Reset complete.")
            self.msg_reset_seccess()

        elif resp_len < 0:
            self.statusbar.showMessage(" Reset/Factory failed: no response from device.")

        self.object_config()

    def factory_result(self, resp_len):
        if resp_len > 0:
            self.statusbar.showMessage(" Factory reset complete.")
            self.msg_factory_seccess()

        elif resp_len < 0:
            self.statusbar.showMessage(" Reset/Factory failed: no response from device.")

        self.object_config()

    def do_reset(self):
        if len(self.list_device.selectedItems()) == 0:
            self.logging.info("Device is not selected")
            self.msg_dev_not_selected()
        else:
            self.sock_close()

            self.selected_devinfo()
            mac_addr = self.curr_mac

            cmd_list = self.wizmakecmd.reset(mac_addr, self.code, self.encoded_setting_pw, self.curr_dev)
            self.logging.info("Reset: %s" % cmd_list)

            self.socket_config()

            self.wizmsghandler = WIZMSGHandler(self.conf_sock, cmd_list, "udp", OP_SETCOMMAND, 2)
            self.wizmsghandler.set_result.connect(self.reset_result)
            self.wizmsghandler.start()

    def do_factory_reset(self, mode):
        if len(self.list_device.selectedItems()) == 0:
            self.logging.info("Device is not selected")
            self.msg_dev_not_selected()
        else:
            self.sock_close()

            self.statusbar.showMessage(" Factory reset?")
            self.selected_devinfo()
            mac_addr = self.curr_mac

            # Factory reset option
            if mode == "setting":
                cmd_list = self.wizmakecmd.factory_reset(
                    mac_addr, self.code, self.encoded_setting_pw, self.curr_dev, ""
                )
            elif mode == "firmware":
                cmd_list = self.wizmakecmd.factory_reset(
                    mac_addr, self.code, self.encoded_setting_pw, self.curr_dev, "0"
                )

            self.logging.info("Factory: %s" % cmd_list)

            self.socket_config()

            if self.unicast_ip.isChecked():
                self.wizmsghandler = WIZMSGHandler(self.conf_sock, cmd_list, "tcp", OP_SETCOMMAND, 2)
            else:
                self.wizmsghandler = WIZMSGHandler(self.conf_sock, cmd_list, "udp", OP_SETCOMMAND, 2)
            self.wizmsghandler.set_result.connect(self.factory_result)
            self.wizmsghandler.start()

    # To set the wait time when no response from the device when searching
    def input_search_wait_time(self):
        self.search_wait_time, okbtn = QtWidgets.QInputDialog.getInt(
            self,
            "Set the wating time for search",
            "Input wating time for search:\n(Default: 3 seconds)",
            self.search_wait_time,
            2,
            10,
            1,
        )
        if okbtn:
            self.logging.info(self.search_wait_time)
            self.search_pre_wait_time = self.search_wait_time
        else:
            pass

    def input_retry_search(self):
        inputdlg = QtWidgets.QInputDialog(self)
        name = "Do Search"
        inputdlg.setOkButtonText(name)
        self.retry_search_num, okbtn = inputdlg.getInt(
            self,
            "Retry search devices",
            "Search for additional devices,\nand the list of detected devices is maintained.\n\nInput for search retry number(option):",
            self.retry_search_num,
            1,
            10,
            1,
        )

        if okbtn:
            self.logging.info(self.retry_search_num)
            self.do_search_retry(self.retry_search_num)
        else:
            # self.do_search_retry(1)
            pass

    def about_info(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setTextFormat(QtCore.Qt.RichText)
        text = "<div style=text-align:center>   \
                    <font size=5 color=darkblue>About WIZnet Configuration Tool</font><br>  \
                    <a href='https://github.com/Wiznet/WIZnet-S2E-Tool-GUI'><br><font color=darkblue size=4>* Github repository</font></a>    \
                    <a href='http://www.wiznet.io/'><font color=black>WIZnet Official homepage</font></a> \
                    <br><a href='https://forum.wiznet.io/'><font color=black>WIZnet Forum</font></a>  \
                    <br><a href='https://wizwiki.net/'><font color=black>WIZnet Wiki</font></a>   \
                    <br><br>2020 WIZnet Co.</font><br>    \
                </div>"
        msgbox.about(self, "About WIZnet-S2E-Tool-GUI", text)

    def msg_not_support(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Not supported device")
        msgbox.setTextFormat(QtCore.Qt.RichText)
        text = (
            "The device is not supported.<br>Please contact us by the link below.<br><br>"
            "<a href='https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/issues'># Github issue page</a>"
        )
        msgbox.setText(text)
        msgbox.exec_()

    def msg_invalid(self, params):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Invalid parameter")
        msgbox.setText("Invalid parameter.\nPlease check the values.")
        msgbox.setInformativeText(params)
        msgbox.exec_()

        self.object_config()

    def msg_dev_not_selected(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Warning")
        msgbox.setText("Device is not selected.")
        msgbox.exec_()

    def msg_invalid_response(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Invalid Response")
        msgbox.setText(
            "Did not receive a valid response from the device.\nPlease check if the device is supported device or firmware is the latest version."
        )
        msgbox.exec_()

    def msg_set_warning(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Warning: Setting")
        msgbox.setText("Setting did not well.\nPlease check the device or check the firmware version.")
        msgbox.exec_()

    def msg_set_error(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Setting Failed")
        msgbox.setText("Setting failed.\nNo response from device.")
        msgbox.exec_()

    def msg_setting_pw_error(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Setting Failed")
        msgbox.setText("Setting failed.\nWrong password.")
        msgbox.exec_()

    def msg_set_success(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.question(self, "Setting success", "Device configuration complete!", QtWidgets.QMessageBox.Yes)

    def msg_certificate_success(self, filename):
        msgbox = QtWidgets.QMessageBox(self)
        text = "Certificate downlaod complete!\n%s" % filename
        msgbox.question(self, "Certificate download success", text, QtWidgets.QMessageBox.Yes)

    def msg_upload_warning(self, dst_ip):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Warning: upload/update")
        msgbox.setText(
            "Destination IP is unreachable: %s\nPlease check if the device is in the same subnet with the PC." % dst_ip
        )
        msgbox.exec_()

    def msg_upload_failed(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Critical)
        msgbox.setWindowTitle("Error: Firmware upload")
        msgbox.setText("Firmware update failed.\nPlease check the device's status.")
        msgbox.exec_()

    def msg_upload_success(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.question(self, "Firmware upload success", "Firmware update complete!", QtWidgets.QMessageBox.Yes)

    def msg_connection_failed(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Critical)
        msgbox.setWindowTitle("Error: Connection failed")
        msgbox.setText("Network connection failed.\nConnection is refused.")
        msgbox.exec_()

    def msg_not_connected(self, dst_ip):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.setIcon(QtWidgets.QMessageBox.Warning)
        msgbox.setWindowTitle("Warning: Network")
        msgbox.setText("Destination IP is unreachable: %s\nPlease check the network status." % dst_ip)
        msgbox.exec_()

    def msg_reset(self):
        self.statusbar.showMessage(" Reset device?")
        msgbox = QtWidgets.QMessageBox(self)
        btnReply = msgbox.question(
            self,
            "Reset",
            "Do you really want to reset the device?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if btnReply == QtWidgets.QMessageBox.Yes:
            self.do_reset()

    def msg_reset_seccess(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.question(self, "Reset", "Reset complete!", QtWidgets.QMessageBox.Yes)

    def msg_factory_seccess(self):
        msgbox = QtWidgets.QMessageBox(self)
        msgbox.question(self, "Factory Reset", "Factory reset complete!", QtWidgets.QMessageBox.Yes)

    def msg_factory_setting(self):
        msgbox = QtWidgets.QMessageBox(self)
        btnReply = msgbox.question(
            self,
            "Factory default settings",
            "Do you really want to factory reset?\nAll settings will be initialized.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if btnReply == QtWidgets.QMessageBox.Yes:
            self.do_factory_reset("setting")

    def msg_factory_firmware(self):
        # factory reset firmware
        msgbox = QtWidgets.QMessageBox(self)
        btnReply = msgbox.question(
            self,
            "Factory default firmware",
            "Do you really want to factory reset the firmware?\nThe firmware and all settings will be initialized to factory default.",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if btnReply == QtWidgets.QMessageBox.Yes:
            self.do_factory_reset("firmware")

    def msg_exit(self):
        msgbox = QtWidgets.QMessageBox(self)
        btnReply = msgbox.question(
            self, "Exit", "Do you really close this program?", QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if btnReply == QtWidgets.QMessageBox.Yes:
            self.close()

    def config_button_icon(self, iconfile, btnname):
        button = getattr(self, btnname)

        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(resource_path(iconfile)), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        button.setIcon(icon)
        button.setIconSize(QtCore.QSize(40, 40))
        button.setFont(self.midfont)

    def set_btn_icon(self):
        self.config_button_icon("gui/search_48.ico", "btn_search")
        self.config_button_icon("gui/setting_48.ico", "btn_setting")
        self.config_button_icon("gui/reset_48.ico", "btn_reset")
        self.config_button_icon("gui/factory_48.ico", "btn_factory")
        self.config_button_icon("gui/exit_48.ico", "btn_exit")

    def font_init(self):
        self.midfont = QtGui.QFont()
        self.midfont.setPixelSize(12)  # pointsize(9)

        self.smallfont = QtGui.QFont()
        self.smallfont.setPixelSize(11)

        self.certfont = QtGui.QFont()
        self.certfont.setPixelSize(10)
        self.certfont.setFamily("Consolas")

    def gui_init(self):
        self.font_init()

        # fix font pixel size
        self.centralwidget.setFont(self.midfont)
        self.list_device.setFont(self.smallfont)
        for i in range(self.list_device.columnCount()):
            self.list_device.horizontalHeaderItem(i).setFont(self.smallfont)

        self.generalTab.setFont(self.smallfont)


class ThreadProgress(QtCore.QThread):
    change_value = QtCore.pyqtSignal(int)

    def __init__(self, parent=None):
        # QtCore.QThread.__init__(self)
        super().__init__()
        self.cnt = 1

    def run(self):
        self.cnt = 1
        while self.cnt <= 100:
            self.cnt += 1
            self.change_value.emit(self.cnt)
            self.msleep(15)

    def __del__(self):
        print("thread: del")
        self.wait()


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    wizwindow = WIZWindow()
    wizwindow.show()
    app.exec_()
