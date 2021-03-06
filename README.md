- [Overview](#overview)
  - [Support Devices](#support-devices)
- [Wiki](#wiki)
- [Environment](#environment)
  - [Windows](#windows)
  - [Linux](#linux)
- [CLI Configuration Tool](#cli-configuration-tool)
- [TroubleShooting](#troubleshooting)

---

# Overview

WIZnet-S2E-Tool-GUI is Configuration Tool for WIZnet serial to ethernet devices.

Python interpreter based and it is platform independent. It works on version 3.x python.

<img src="https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/blob/master/doc/images/wizconfig_main_V1.0.0.png" width="85%"></img>

---

## Support Devices

### 1 Port Serial to Ethernet Module

- [WIZ750SR](http://wizwiki.net/wiki/doku.php?id=products:wiz750sr:start)
  - [WIZ750SR Github page](https://github.com/Wiznet/WIZ750SR)
- [WIZ750SR-100](http://wizwiki.net/wiki/doku.php?id=products:wiz750sr-100:start)
- [WIZ750SR-105](http://wizwiki.net/wiki/doku.php?id=products:wiz750sr-105:start)
- [WIZ750SR-110](http://wizwiki.net/wiki/doku.php?id=products:wiz750sr-110:start)
- [WIZ107SR](http://www.wiznet.io/product-item/wiz107sr/) & [WIZ108SR](http://www.wiznet.io/product-item/wiz108sr/)

### 2 Port Serial to Ethernet Module

- [WIZ752SR-120](https://wizwiki.net/wiki/doku.php?id=products:s2e_module:wiz752sr-120:start)
- [WIZ752SR-125](https://wizwiki.net/wiki/doku.php?id=products:s2e_module:wiz752sr-125:start)

### Pre-programmed MCU
- [W7500(P)-S2E](http://wizwiki.net/wiki/doku.php?id=products:w7500x-s2e:en)

---

# Wiki

New to the WIZnet Configuration Tool? Visit the Wiki page.

The wiki page contains getting started guides, how to use tool, and troubleshooting guides.

You can check the contents of configuration tool wiki on the [Wiki tab.](https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/wiki)

---

# Environment

## Windows

You can refer to below wiki page.

- [WIZnet-S2E-Tool-GUI wiki: Getting started guide](https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/wiki/Getting-started-guide)

* Windows 7

  - If the Windows 7 service pack version is low, there may be a problem running this tool.

* Windows 10

Recommended to use tool at a resolution of **1440\*900 or higher.**

You can download Windows excutable file from [release page.](https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/releases)

## Linux

You can refer to below wiki page.

- [Getting started guide: Using Python - Linux](https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/wiki/Getting-started-guide#using-python-linux)

### Ubuntu

WIZnet-S2E-Tool-GUI is worked on **python 3.x** version.

So please check the version.

    $ python --version

Install:

    $ git clone https://github.com/Wiznet/WIZnet-S2E-Tool-GUI
    $ cd WIZnet-S2E-Tool-GUI
    $ sudo pip install -r requirements.txt

Now, run the configuration tool.

    $ python main.py

You can use the [CLI configuration tool](https://github.com/Wiznet/WIZnet-S2E-Tool) also.

---

# CLI Configuration Tool

In addition to this GUI configuration tool, we provides a command line based configuration tool.

With just a few options, you can easily set up your device.

One of the features of the CLI tool is that **it supports multi device configuration**. If you have multiple devices, try it.

CLI configuration tool can be refer from [WIZnet-S2E-Tool github page.](https://github.com/Wiznet/WIZnet-S2E-Tool)

---

# TroubleShooting

If you have any problems, use one of the links below and **please report the problem.**

- [Github Issue page](https://github.com/Wiznet/WIZnet-S2E-Tool-GUI/issues)
- [WIZnet Forum](https://forum.wiznet.io/)

---
