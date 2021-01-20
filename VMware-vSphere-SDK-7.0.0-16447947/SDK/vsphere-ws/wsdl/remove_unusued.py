#!/usr/bin/env python

import os
import shutil
from lxml import etree

allowedOps = {'RetrieveServiceContent', 'Login', 'RetrievePropertiesEx', 'InitiateFileTransferToGuest', 'ListProcessesInGuest', 'InitiateFileTransferFromGuest', 'FindByIp', 'ListFilesInGuest', 'StartProgramInGuest', 'MoveFileInGuest', 'DeleteFileInGuest', 'FindByInventoryPath', 'FindChild', 'RetrieveProperties', 'FindAllByDnsName', 'FindAllByIp', }

defaultAllowedElements = {"versionURI", "MethodFaultFault", "RuntimeFaultFault", \
    "HostCommunicationFault", "HostNotConnectedFault", "HostNotReachableFault", \
    "InvalidArgumentFault", "InvalidRequestFault", "InvalidTypeFault", \
    "ManagedObjectNotFoundFault", "MethodNotFoundFault", "NotEnoughLicensesFault", \
    "NotImplementedFault", "NotSupportedFault", "RequestCanceledFault", "SecurityErrorFault", \
    "SystemErrorFault", "UnexpectedFaultFault", "InvalidCollectorVersionFault", \
    "InvalidPropertyFault"}

defaultKeepTypes = { 'NamePasswordAuthentication', 'ExecuteOptions', 'GuestProgramSpec', 'GuestWindowsFileAttributes', 'GuestWindowsProgramSpec', 'Datacenter', 'VirtualMachine', 'Folder', 'GuestInfo', 'VirtualMachineConfigInfo', 'Network'}

minipath = 'vim25-mini'

def filterByAttrVal(element, attrName, xpath, allowed):
    for op in element.findall(xpath, element.nsmap):
        if op.attrib[attrName] not in allowed:
            element.remove(op)

def getTypesFromPort(portTyp):
    ret = set()
    for op in portTyp.getchildren():
        ret.update({child.attrib['message'].lstrip('vim25:') for child in op.getchildren()})
    return ret

def getElementName(message):
    return message.find('./').attrib['element'].lstrip('vim25:')

def getBaseTypenames(complexType):
    bases = complexType.findall('./complexContent/extension', complexType.nsmap)
    return { b.attrib['base'].lstrip('vim25:') for b in bases }

def getMemberTypenames(complexType):
    bases = complexType.findall('./complexContent/extension/sequence/element', complexType.nsmap)
    return { b.attrib['type'].lstrip('vim25:') for b in bases }

def getComplexType(bschema, name):
    return bschema.find("complexType[@name='{}']".format(name), bschema.nsmap)

def getBaseAndMembers(bschema, name):
    alreadySeen = set()
    def _addBaseAndMembers(bschema, name):
        alreadySeen.add(name)
        xtype = getComplexType(bschema, name)
        if xtype is None:
            return
        refTypes = getBaseTypenames(xtype)
        refTypes.update(getMemberTypenames(xtype))
        for bt in refTypes:
            if bt not in alreadySeen:
                _addBaseAndMembers(bschema, bt)
    _addBaseAndMembers(bschema, name)
    return alreadySeen

def write(etre, name):
    etre.write(name, pretty_print=True, encoding='UTF-8', xml_declaration=True)

def main():
    if os.path.exists(minipath) and os.path.isdir(minipath):
        shutil.rmtree(minipath)
    shutil.copytree('vim25', minipath)

    vim = etree.parse('vim25-mini/vim.wsdl')
    definitions = vim.getroot()
    portType = definitions.find('portType', definitions.nsmap)
    binding = definitions.find('binding', definitions.nsmap)
    filterByAttrVal(portType, 'name', 'operation', allowedOps)
    filterByAttrVal(binding, 'name', 'operation', allowedOps)
    allowedMessages = getTypesFromPort(portType)
    filterByAttrVal(definitions, 'name', 'message', allowedMessages)
    allowedElements = {getElementName(msg) for msg in definitions.findall("message", definitions.nsmap)}
    allowedElements.update(defaultAllowedElements)
    typesSchema = definitions.find('types/xsd:schema', definitions.nsmap)
    filterByAttrVal(typesSchema, 'name', 'element', allowedElements)

    allowedMessageTypes = { t.attrib.get('type') for t in typesSchema.findall('element', typesSchema.nsmap)}
    if None in allowedMessageTypes:
        allowedMessageTypes.remove(None)
    allowedMessageTypes = { i.lstrip("vim25:") for i in allowedMessageTypes}

    allowedVimTypes = defaultKeepTypes
    for elem in typesSchema.findall('element', typesSchema.nsmap):
        for ct in elem.findall('complexType', elem.nsmap):
            seq = ct.find('sequence', ct.nsmap)
            if seq is None:
                continue
            for el in seq.findall('element', seq.nsmap):
                typeName = el.attrib.get('type')
                if typeName:
                    allowedVimTypes.add(typeName.lstrip('vim25:'))
    allowedVimTypes.update(allowedMessageTypes)
    write(vim, 'vim25-mini/vim.wsdl')

    ## find all referenced types in vim-types and vim-messagetypes
    vimTypes = etree.parse('vim25-mini/vim-types.xsd')
    vimTypesSchema = vimTypes.getroot()

    messageTypes = etree.parse('vim25-mini/vim-messagetypes.xsd')
    messageTypesSchema = messageTypes.getroot()

    referencedTypes = set()
    for name in allowedVimTypes:
        referencedTypes |= getBaseAndMembers(vimTypesSchema, name)
        referencedTypes |= getBaseAndMembers(messageTypesSchema, name)

    ## rewrite vim-types.xsd
    filterByAttrVal(vimTypesSchema, 'name', 'complexType', referencedTypes)
    filterByAttrVal(vimTypesSchema, 'name', 'simpleType', referencedTypes)
    write(vimTypes, 'vim25-mini/vim-types.xsd')

    ## rewrite vim-messagetypes.xsd
    filterByAttrVal(messageTypesSchema, 'name', 'complexType', referencedTypes)
    write(messageTypes, 'vim25-mini/vim-messagetypes.xsd')

if __name__ == "__main__":
    main()
