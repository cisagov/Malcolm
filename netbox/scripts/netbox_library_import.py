#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

# adapted from minitriga/Netbox-Device-Type-Library-Import (MIT License)
# Copyright (c) 2021 Alexander Gittings
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from collections import Counter
import logging
import yaml
import pynetbox
import glob
import os
import re


def slugFormat(name):
    return re.sub(r'\W+', '-', name.lower())


YAML_EXTENSIONS = ['yml', 'yaml']


def getFiles(library_dir, vendors=None):
    files = []
    discoveredVendors = []
    base_path = os.path.join(library_dir, 'device-types', '')
    if vendors:
        for r, d, f in os.walk(base_path):
            for folder in d:
                for vendor in vendors:
                    if vendor.lower() == folder.lower():
                        discoveredVendors.append({'name': folder, 'slug': slugFormat(folder)})
                        for extension in YAML_EXTENSIONS:
                            files.extend(glob.glob(base_path + folder + f'/*.{extension}'))
    else:
        for r, d, f in os.walk(base_path):
            for folder in d:
                if folder.lower() != "Testing":
                    discoveredVendors.append({'name': folder, 'slug': slugFormat(folder)})
        for extension in YAML_EXTENSIONS:
            files.extend(glob.glob(base_path + f'[!Testing]*/*.{extension}'))
    return files, discoveredVendors


def get_files_modules(library_dir, vendors=None):
    '''Get files list for modules.

    Args:
        vendors: List of vendors to sync or None to sync all vendors.

    Returns:
        A 2-tuple of:
        - list of filenames found
        - list of vendors found

    '''

    files = []
    discoveredVendors = []
    base_path = os.path.join(library_dir, 'module-types', '')
    if vendors:
        for r, d, f in os.walk(base_path):
            for folder in d:
                for vendor in vendors:
                    if vendor.lower() == folder.lower():
                        discoveredVendors.append({'name': folder, 'slug': slugFormat(folder)})
                        for extension in YAML_EXTENSIONS:
                            files.extend(glob.glob(base_path + folder + f'/*.{extension}'))
    else:
        for r, d, f in os.walk(base_path):
            for folder in d:
                if folder.lower() != "Testing":
                    discoveredVendors.append({'name': folder, 'slug': slugFormat(folder)})
        for extension in YAML_EXTENSIONS:
            files.extend(glob.glob(base_path + f'[!Testing]*/*.{extension}'))

    return files, discoveredVendors


def readYAMl(files, **kwargs):
    slugs = kwargs.get('slugs', None)
    deviceTypes = []
    manufacturers = []
    for file in files:
        with open(file, 'r') as stream:
            try:
                data = yaml.safe_load(stream)
            except yaml.YAMLError:
                continue
            manufacturer = data['manufacturer']
            data['manufacturer'] = {}
            data['manufacturer']['name'] = manufacturer
            data['manufacturer']['slug'] = slugFormat(manufacturer)

        if slugs and data['slug'] not in slugs:
            continue

        deviceTypes.append(data)
        manufacturers.append(manufacturer)
    return deviceTypes


def read_yaml_modules(files, **kwargs):
    slugs = kwargs.get('slugs', None)
    module_types = []
    manufacturers = []
    for file in files:
        with open(file, 'r') as stream:
            try:
                data = yaml.safe_load(stream)
            except yaml.YAMLError:
                continue
            manufacturer = data['manufacturer']
            data['manufacturer'] = {}
            data['manufacturer']['name'] = manufacturer
            data['manufacturer']['slug'] = slugFormat(manufacturer)

        if slugs and data['slug'] not in slugs:
            continue

        module_types.append(data)
        manufacturers.append(manufacturer)
    return module_types


def createManufacturers(vendors, nb, counter=None):
    all_manufacturers = {str(item): item for item in nb.dcim.manufacturers.all()}
    need_manufacturers = []
    for vendor in vendors:
        try:
            manGet = all_manufacturers[vendor["name"]]
        except KeyError:
            need_manufacturers.append(vendor)

    if not need_manufacturers:
        return

    try:
        manSuccess = nb.dcim.manufacturers.create(need_manufacturers)
        if counter is not None:
            for man in manSuccess:
                counter.update({'manufacturer': 1})
    except pynetbox.RequestError:
        pass


def createInterfaces(interfaces, deviceType, nb, counter=None):
    all_interfaces = {str(item): item for item in nb.dcim.interface_templates.filter(devicetype_id=deviceType)}
    need_interfaces = []
    for interface in interfaces:
        try:
            ifGet = all_interfaces[interface["name"]]
        except KeyError:
            interface['device_type'] = deviceType
            need_interfaces.append(interface)

    if not need_interfaces:
        return

    try:
        ifSuccess = nb.dcim.interface_templates.create(need_interfaces)
        if counter is not None:
            for intf in ifSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_interfaces(interfaces, module_type, nb, counter=None):
    all_interfaces = {str(item): item for item in nb.dcim.interface_templates.filter(moduletype_id=module_type)}
    need_interfaces = []
    for interface in interfaces:
        try:
            if_res = all_interfaces[interface["name"]]
        except KeyError:
            interface['module_type'] = module_type
            need_interfaces.append(interface)

    if not need_interfaces:
        return

    try:
        ifSuccess = nb.dcim.interface_templates.create(need_interfaces)
        if counter is not None:
            for intf in ifSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createConsolePorts(consoleports, deviceType, nb, counter=None):
    all_consoleports = {str(item): item for item in nb.dcim.console_port_templates.filter(devicetype_id=deviceType)}
    need_consoleports = []
    for consoleport in consoleports:
        try:
            cpGet = all_consoleports[consoleport["name"]]
        except KeyError:
            consoleport['device_type'] = deviceType
            need_consoleports.append(consoleport)

    if not need_consoleports:
        return

    try:
        cpSuccess = nb.dcim.console_port_templates.create(need_consoleports)
        if counter is not None:
            for port in cpSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_console_ports(consoleports, module_type, nb, counter=None):
    all_consoleports = {str(item): item for item in nb.dcim.console_port_templates.filter(moduletype_id=module_type)}
    need_consoleports = []
    for consoleport in consoleports:
        try:
            cpGet = all_consoleports[consoleport["name"]]
        except KeyError:
            consoleport['module_type'] = module_type
            need_consoleports.append(consoleport)

    if not need_consoleports:
        return

    try:
        cpSuccess = nb.dcim.console_port_templates.create(need_consoleports)
        if counter is not None:
            for port in cpSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createPowerPorts(powerports, deviceType, nb, counter=None):
    all_power_ports = {str(item): item for item in nb.dcim.power_port_templates.filter(devicetype_id=deviceType)}
    need_power_ports = []
    for powerport in powerports:
        try:
            ppGet = all_power_ports[powerport["name"]]
        except KeyError:
            powerport['device_type'] = deviceType
            need_power_ports.append(powerport)

    if not need_power_ports:
        return

    try:
        ppSuccess = nb.dcim.power_port_templates.create(need_power_ports)
        if counter is not None:
            for pp in ppSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_power_ports(powerports, module_type, nb, counter=None):
    all_power_ports = {str(item): item for item in nb.dcim.power_port_templates.filter(moduletype_id=module_type)}
    need_power_ports = []
    for powerport in powerports:
        try:
            ppGet = all_power_ports[powerport["name"]]
        except KeyError:
            powerport['module_type'] = module_type
            need_power_ports.append(powerport)

    if not need_power_ports:
        return

    try:
        ppSuccess = nb.dcim.power_port_templates.create(need_power_ports)
        if counter is not None:
            for pp in ppSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createConsoleServerPorts(consoleserverports, deviceType, nb, counter=None):
    all_consoleserverports = {
        str(item): item for item in nb.dcim.console_server_port_templates.filter(devicetype_id=deviceType)
    }
    need_consoleserverports = []
    for csport in consoleserverports:
        try:
            cspGet = all_consoleserverports[csport["name"]]
        except KeyError:
            csport['device_type'] = deviceType
            need_consoleserverports.append(csport)

    if not need_consoleserverports:
        return

    try:
        cspSuccess = nb.dcim.console_server_port_templates.create(need_consoleserverports)
        if counter is not None:
            for csp in cspSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_console_server_ports(consoleserverports, module_type, nb, counter=None):
    all_consoleserverports = {
        str(item): item for item in nb.dcim.console_server_port_templates.filter(moduletype_id=module_type)
    }
    need_consoleserverports = []
    for csport in consoleserverports:
        try:
            cspGet = all_consoleserverports[csport["name"]]
        except KeyError:
            csport['module_type'] = module_type
            need_consoleserverports.append(csport)

    if not need_consoleserverports:
        return

    try:
        cspSuccess = nb.dcim.console_server_port_templates.create(need_consoleserverports)
        if counter is not None:
            for csp in cspSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createFrontPorts(frontports, deviceType, nb, counter=None):
    all_frontports = {str(item): item for item in nb.dcim.front_port_templates.filter(devicetype_id=deviceType)}
    need_frontports = []
    for frontport in frontports:
        try:
            fpGet = all_frontports[frontport["name"]]
        except KeyError:
            frontport['device_type'] = deviceType
            need_frontports.append(frontport)

    if not need_frontports:
        return

    all_rearports = {str(item): item for item in nb.dcim.rear_port_templates.filter(devicetype_id=deviceType)}
    for port in need_frontports:
        try:
            rpGet = all_rearports[port["rear_port"]]
            port['rear_port'] = rpGet.id
        except KeyError:
            pass

    try:
        fpSuccess = nb.dcim.front_port_templates.create(need_frontports)
        if counter is not None:
            for fp in fpSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_front_ports(frontports, module_type, nb, counter=None):
    all_frontports = {str(item): item for item in nb.dcim.front_port_templates.filter(moduletype_id=module_type)}
    need_frontports = []
    for frontport in frontports:
        try:
            fpGet = all_frontports[frontport["name"]]
        except KeyError:
            frontport['module_type'] = module_type
            need_frontports.append(frontport)

    if not need_frontports:
        return

    all_rearports = {str(item): item for item in nb.dcim.rear_port_templates.filter(moduletype_id=module_type)}
    for port in need_frontports:
        try:
            rpGet = all_rearports[port["rear_port"]]
            port['rear_port'] = rpGet.id
        except KeyError:
            pass

    try:
        fpSuccess = nb.dcim.front_port_templates.create(need_frontports)
        if counter is not None:
            for fp in fpSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createRearPorts(rearports, deviceType, nb, counter=None):
    all_rearports = {str(item): item for item in nb.dcim.rear_port_templates.filter(devicetype_id=deviceType)}
    need_rearports = []
    for rearport in rearports:
        try:
            rpGet = all_rearports[rearport["name"]]
        except KeyError:
            rearport['device_type'] = deviceType
            need_rearports.append(rearport)

    if not need_rearports:
        return

    try:
        rpSuccess = nb.dcim.rear_port_templates.create(need_rearports)
        if counter is not None:
            for rp in rpSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_rear_ports(rearports, module_type, nb, counter=None):
    all_rearports = {str(item): item for item in nb.dcim.rear_port_templates.filter(moduletype_id=module_type)}
    need_rearports = []
    for rearport in rearports:
        try:
            rpGet = all_rearports[rearport["name"]]
        except KeyError:
            rearport['module_type'] = module_type
            need_rearports.append(rearport)

    if not need_rearports:
        return

    try:
        rpSuccess = nb.dcim.rear_port_templates.create(need_rearports)
        if counter is not None:
            for rp in rpSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createDeviceBays(devicebays, deviceType, nb, counter=None):
    all_devicebays = {str(item): item for item in nb.dcim.device_bay_templates.filter(devicetype_id=deviceType)}
    need_devicebays = []
    for devicebay in devicebays:
        try:
            dbGet = all_devicebays[devicebay["name"]]
        except KeyError:
            devicebay['device_type'] = deviceType
            need_devicebays.append(devicebay)

    if not need_devicebays:
        return

    try:
        dbSuccess = nb.dcim.device_bay_templates.create(need_devicebays)
        if counter is not None:
            for db in dbSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_bays(module_bays, device_type, nb, counter=None):
    '''Create module bays.

    Args:
        module_bays: parsed YAML module_bays section.
        device_type: the device type instance from netbox.
        nb: Netbox API instance
    '''
    all_module_bays = {str(item): item for item in nb.dcim.module_bay_templates.filter(devicetype_id=device_type)}
    need_module_bays = []
    for module_bay in module_bays:
        try:
            dbGet = all_module_bays[module_bay["name"]]
        except KeyError:
            module_bay['device_type'] = device_type
            need_module_bays.append(module_bay)

    if not need_module_bays:
        return

    try:
        module_bay_res = nb.dcim.module_bay_templates.create(need_module_bays)
        if counter is not None:
            for module_bay in module_bay_res:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def createPowerOutlets(poweroutlets, deviceType, nb, counter=None):
    all_poweroutlets = {str(item): item for item in nb.dcim.power_outlet_templates.filter(devicetype_id=deviceType)}
    need_poweroutlets = []
    for poweroutlet in poweroutlets:
        try:
            poGet = all_poweroutlets[poweroutlet["name"]]
        except KeyError:
            poweroutlet["device_type"] = deviceType
            need_poweroutlets.append(poweroutlet)

    if not need_poweroutlets:
        return

    all_power_ports = {str(item): item for item in nb.dcim.power_port_templates.filter(devicetype_id=deviceType)}
    for outlet in need_poweroutlets:
        try:
            ppGet = all_power_ports[outlet["power_port"]]
            outlet['power_port'] = ppGet.id
        except KeyError:
            pass

    try:
        poSuccess = nb.dcim.power_outlet_templates.create(need_poweroutlets)
        if counter is not None:
            for po in poSuccess:
                counter.update({'updated': 1})
    except pynetbox.RequestError:
        pass


def create_module_power_outlets(poweroutlets, module_type, nb, counter=None):
    '''Create missing module power outlets.

    Args:
        poweroutlets: YAML power outlet data.
        module_type: Netbox module_type instance.
        nb: pynetbox API instance.

    Returns:
        None

    Raises:
        None
    '''
    all_poweroutlets = {str(item): item for item in nb.dcim.power_outlet_templates.filter(moduletype_id=module_type)}
    need_poweroutlets = []
    for poweroutlet in poweroutlets:
        try:
            poGet = all_poweroutlets[poweroutlet["name"]]
        except KeyError:
            poweroutlet["module_type"] = module_type
            need_poweroutlets.append(poweroutlet)

    if not need_poweroutlets:
        return

    all_power_ports = {str(item): item for item in nb.dcim.power_port_templates.filter(moduletype_id=module_type)}
    for outlet in need_poweroutlets:
        try:
            ppGet = all_power_ports[outlet["power_port"]]
            outlet['power_port'] = ppGet.id
        except KeyError:
            pass

    try:
        poSuccess = nb.dcim.power_outlet_templates.create(need_poweroutlets)
        if counter is not None:
            for po in poSuccess:
                counter.update({'module_port_added': 1})
    except pynetbox.RequestError:
        pass


def createDeviceTypes(deviceTypes, nb, counter=None):
    all_device_types = {str(item): item for item in nb.dcim.device_types.all()}
    for deviceType in deviceTypes:
        try:
            dt = all_device_types[deviceType["model"]]
        except KeyError:
            try:
                dt = nb.dcim.device_types.create(deviceType)
                if counter is not None:
                    counter.update({'added': 1})
            except pynetbox.RequestError:
                pass

        if "interfaces" in deviceType:
            createInterfaces(deviceType["interfaces"], dt.id, nb, counter=counter)
        if "power-ports" in deviceType:
            createPowerPorts(deviceType["power-ports"], dt.id, nb, counter=counter)
        if "power-port" in deviceType:
            createPowerPorts(deviceType["power-port"], dt.id, nb, counter=counter)
        if "console-ports" in deviceType:
            createConsolePorts(deviceType["console-ports"], dt.id, nb, counter=counter)
        if "power-outlets" in deviceType:
            createPowerOutlets(deviceType["power-outlets"], dt.id, nb, counter=counter)
        if "console-server-ports" in deviceType:
            createConsoleServerPorts(deviceType["console-server-ports"], dt.id, nb, counter=counter)
        if "rear-ports" in deviceType:
            createRearPorts(deviceType["rear-ports"], dt.id, nb, counter=counter)
        if "front-ports" in deviceType:
            createFrontPorts(deviceType["front-ports"], dt.id, nb, counter=counter)
        if "device-bays" in deviceType:
            createDeviceBays(deviceType["device-bays"], dt.id, nb, counter=counter)
        if "module-bays" in deviceType:
            create_module_bays(deviceType['module-bays'], dt.id, nb, counter=counter)


def create_module_types(module_types, nb, counter=None):
    '''Create missing module types.

    Args:
        module_types: yaml data from repo.
        nb: pynetbox API instance

    Returns:
        None
    '''

    all_module_types = {}
    for curr_nb_mt in nb.dcim.module_types.all():
        if curr_nb_mt.manufacturer.slug not in all_module_types:
            all_module_types[curr_nb_mt.manufacturer.slug] = {}

        all_module_types[curr_nb_mt.manufacturer.slug][curr_nb_mt.model] = curr_nb_mt

    for curr_mt in module_types:
        try:
            module_type_res = all_module_types[curr_mt['manufacturer']['slug']][curr_mt["model"]]
        except KeyError:
            try:
                module_type_res = nb.dcim.module_types.create(curr_mt)
                if counter is not None:
                    counter.update({'module_added': 1})
            except pynetbox.RequestError:
                pass

        # module_type_res = all_module_types[curr_mt['manufacturer']['slug']][curr_mt["model"]]

        if "interfaces" in curr_mt:
            create_module_interfaces(curr_mt["interfaces"], module_type_res.id, nb, counter=counter)
        if "power-ports" in curr_mt:
            create_module_power_ports(curr_mt["power-ports"], module_type_res.id, nb, counter=counter)
        if "console-ports" in curr_mt:
            create_module_console_ports(curr_mt["console-ports"], module_type_res.id, nb, counter=counter)
        if "power-outlets" in curr_mt:  # No current entries to test
            create_module_power_outlets(curr_mt["power-outlets"], module_type_res.id, nb, counter=counter)
        if "console-server-ports" in curr_mt:  # No current entries to test
            create_module_console_server_ports(curr_mt["console-server-ports"], module_type_res.id, nb, counter=counter)
        if "rear-ports" in curr_mt:
            create_module_rear_ports(curr_mt["rear-ports"], module_type_res.id, nb, counter=counter)
        if "front-ports" in curr_mt:
            create_module_front_ports(curr_mt["front-ports"], module_type_res.id, nb, counter=counter)


def import_library(nb, library_dir):
    cntr = Counter(
        added=0,
        updated=0,
        manufacturer=0,
        module_added=0,
        module_port_added=0,
    )

    if library_dir is not None and os.path.isdir(library_dir):
        files, vendors = getFiles(library_dir)
        deviceTypes = readYAMl(files)
        createManufacturers(vendors, nb, counter=cntr)
        createDeviceTypes(deviceTypes, nb, counter=cntr)

        files, vendors = get_files_modules(library_dir)
        module_types = read_yaml_modules(files)
        createManufacturers(vendors, nb, counter=cntr)
        create_module_types(module_types, nb, counter=cntr)

    return cntr
