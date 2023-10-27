# !/usr/bin/env python3
# -*-coding:utf-8 -*-

"""
# File       : main.py
# Time       ：2022/7/15
# Author     ：Yooha
"""

import os
import sys
import struct
import copy
import binascii 




##https://javaforall.cn/153504.html
#*****************************************************************************************
class ACCESS_FLAGS:
    ACC_PUBLIC       = 0x00000001
    ACC_PRIVATE      = 0x00000002
    ACC_PROTECTED    = 0x00000004
    ACC_STATIC       = 0x00000008
    ACC_FINAL        = 0x00000010
    ACC_SYNCHRONIZED = 0x00000020
    ACC_SUPER        = 0x00000020
    ACC_VOLATILE     = 0x00000040
    ACC_BRIDGE       = 0x00000040
    ACC_TRANSIENT    = 0x00000080
    ACC_VARARGS      = 0x00000080
    ACC_NATIVE       = 0x00000100
    ACC_INTERFACE    = 0x00000200
    ACC_ABSTRACT     = 0x00000400
    ACC_STRICT       = 0x00000800
    ACC_SYNTHETIC    = 0x00001000
    ACC_ANNOTATION   = 0x00002000
    ACC_ENUM         = 0x00004000
    ACC_CONSTRUCTOR  = 0x00010000
    ACC_DECLARED_SYNCHRONIZED = 0x00020000
    ACC_CLASS_MASK = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM)
    ACC_INNER_CLASS_MASK = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC)
    ACC_FIELD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM)
    ACC_METHOD_MASK = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
                | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
                | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
                | ACC_DECLARED_SYNCHRONIZED)

    @classmethod
    def get_access_flags(cls, flags) -> list:
        """
        返回字符串列表
        """
        list_flags = []
        if (flags & cls.ACC_PUBLIC) != 0:
            list_flags.append("ACC_PUBLIC")
        if (flags & cls.ACC_PRIVATE) != 0:
            list_flags.append("ACC_PRIVATE")
        if (flags & cls.ACC_PROTECTED) != 0:
            list_flags.append("ACC_PROTECTED")
        if (flags & cls.ACC_STATIC) != 0:
            list_flags.append("ACC_STATIC")
        if (flags & cls.ACC_FINAL) != 0:
            list_flags.append("ACC_FINAL")
        if (flags & cls.ACC_SYNCHRONIZED) != 0:
            list_flags.append("ACC_SYNCHRONIZED")
        if (flags & cls.ACC_SUPER) != 0:
            list_flags.append("ACC_SUPER")
        if (flags & cls.ACC_VOLATILE) != 0:
            list_flags.append("ACC_VOLATILE")
        if (flags & cls.ACC_BRIDGE) != 0:
            list_flags.append("ACC_BRIDGE")
        if (flags & cls.ACC_TRANSIENT) != 0:
            list_flags.append("ACC_TRANSIENT")
        if (flags & cls.ACC_VARARGS) != 0:
            list_flags.append("ACC_VARARGS")
        if (flags & cls.ACC_NATIVE) != 0:
            list_flags.append("ACC_NATIVE")
        if (flags & cls.ACC_INTERFACE) != 0:
            list_flags.append("ACC_INTERFACE")
        if (flags & cls.ACC_ABSTRACT) != 0:
            list_flags.append("ACC_ABSTRACT")
        if (flags & cls.ACC_STRICT) != 0:
            list_flags.append("ACC_STRICT")
        if (flags & cls.ACC_SYNTHETIC) != 0:
            list_flags.append("ACC_SYNTHETIC")
        if (flags & cls.ACC_ANNOTATION) != 0:
            list_flags.append("ACC_ANNOTATION")
        if (flags & cls.ACC_CONSTRUCTOR) != 0:
            list_flags.append("ACC_CONSTRUCTOR")
        if (flags & cls.ACC_DECLARED_SYNCHRONIZED) != 0:
            list_flags.append("ACC_DECLARED_SYNCHRONIZED")
        return list_flags
#*****************************************************************************************
def parse_uleb128(file):
    ch = struct.unpack('B', file.read(1))[0]
    ret = ch
    if (ch > 0x7F):
        ch = struct.unpack('B', file.read(1))[0]
        ret = (ret & 0x7F) | ((ch & 0x7F) << 7)
        if (ch > 0x7F):
            ch = struct.unpack('B', file.read(1))[0]
            ret = ret | ((ch & 0x7F) << 14)
            if (ch > 0x7F):
                ch = struct.unpack('B', file.read(1))[0]
                ret = ret | ((ch & 0x7F) << 21)
                if (ch > 0x7F):
                    ch = struct.unpack('B', file.read(1))[0]
                    ret = ret | ((ch & 0x7F) << 28)
    #print(ret)
    return ret
#*****************************************************************************************
class Dex_Parse:
    def __init__(self, file):
        self.file = file
        self.parse_header()

    def parse_header(self):
        self.parse_magic()
        self.parse_checksum()
        self.parse_signature()
        self.parse_other()

    def parse_magic(self):
        self.magic:list = []
        for i in range(8):
            ch = self.file.read(1)
            self.magic.append(ch.decode('utf-8'))
        print("read magic = " + str(self.magic))


    def parse_checksum(self):
        # file.seek(0x8) 按顺序读取，所以不需要设置文件偏移
        self.checksum = struct.unpack('I', self.file.read(4))
        print('read checksum = %#x'%self.checksum)


    def parse_signature(self):
        self.signature:list = []
        for i in range(20):
            ch = struct.unpack('B', self.file.read(1))
            self.signature.append(ch[0])
        print("read signeture = " + str(self.signature))


    def parse_other(self):
        self.fileSize = struct.unpack('I', self.file.read(4))[0]
        self.headerSize = struct.unpack('I', self.file.read(4))[0]
        self.endianTag = struct.unpack('I', self.file.read(4))[0]
        self.linkSize = struct.unpack('I', self.file.read(4))[0]
        self.linkOff = struct.unpack('I', self.file.read(4))[0]
        self.mapOff = struct.unpack('I', self.file.read(4))[0]
        self.stringIdsSize = struct.unpack('I', self.file.read(4))[0]
        self.stringIdsOff = struct.unpack('I', self.file.read(4))[0]
        self.typeIdsSize = struct.unpack('I', self.file.read(4))[0]
        self.typeIdsOff = struct.unpack('I', self.file.read(4))[0]
        self.protoIdsSize = struct.unpack('I', self.file.read(4))[0]
        self.protoIdsOff = struct.unpack('I', self.file.read(4))[0]
        self.fieldIdsSize = struct.unpack('I', self.file.read(4))[0]
        self.fieldIdsOff = struct.unpack('I', self.file.read(4))[0]
        self.methodIdsSize = struct.unpack('I', self.file.read(4))[0]
        self.methodIdsOff = struct.unpack('I', self.file.read(4))[0]
        self.classDefsSize = struct.unpack('I', self.file.read(4))[0]
        self.classDefsOff = struct.unpack('I', self.file.read(4))[0]
        self.dataSize = struct.unpack('I', self.file.read(4))[0]
        self.dataOff = struct.unpack('I', self.file.read(4))[0]

    def parse_stringids_index(self, index) -> str:
        """
        该函数用于解析指定索引对应的字符串，并将其返回
        """
        if index > self.stringIdsSize:
            print("索引%s超过DexString的最大尺寸%s"%(index, self.stringIdsSize))
            return
        offset = self.stringIdsOff + index * 4
        self.file.seek(offset)
        string_data_off = struct.unpack('I', self.file.read(4))[0]
        self.file.seek(string_data_off)
        string_len = struct.unpack('B', self.file.read(1))[0]
        string_data = str(self.file.read(string_len), encoding = "utf-8")
        print("%X -> %s"%(index, string_data))
        return string_data


    def parse_typeids_index(self, index) -> int:
        """
        该函数返回typeids对应的stringids的索引
        """
        if index > self.typeIdsSize:
            print("索引%s超过DexType的最大尺寸%s"%(index, self.typeIdsSize))
            return
        offset = self.typeIdsOff + index * 4
        self.file.seek(offset)
        dexcriptor_idx = struct.unpack('I', self.file.read(4))[0]
        print(dexcriptor_idx)
        return dexcriptor_idx


    def parse_protoids_shorty(self, index) -> int:
        """
        该函数返回index对应方法的声明所对应的stringids的索引
        """
        if index > self.protoIdsSize:
            print("索引%s超过DexProto的最大尺寸%s"%(index, self.protoIdsSize))
            return -1
        offset = self.protoIdsOff + index * 4 * 3
        self.file.seek(offset)
        shorty_idx = struct.unpack('I', self.file.read(4))[0]      
        print("%X -> shorty_idx : %X"%(index, shorty_idx))
        return shorty_idx

    def parse_protoids_return_type(self, index) -> list:
        """
        该函数返回index对应方法的返回值对应的typeids的索引
        """
        if index > self.protoIdsSize:
            print("索引%s超过DexProto的最大尺寸%s"%(index, self.protoIdsSize))
            return -1
        offset = self.protoIdsOff + index * 4 * 3 + 4
        self.file.seek(offset)
        return_type_idx = struct.unpack('I', self.file.read(4))[0]      
        print("%X -> return_type_idx : %X"%(index, return_type_idx))
        return return_type_idx

    def parse_protoids_parameters(self, index) -> int:
        """
        该函数返回一个stringids索引的列表, 每个索引为index对应方法的参数对应的typeids的索引
        """
        if index > self.protoIdsSize:
            print("索引%s超过DexProto的最大尺寸%s"%(index, self.protoIdsSize))
            return -1
        offset = self.protoIdsOff + index * 4 * 3 + 4 * 2
        self.file.seek(offset)
        parameters_off = struct.unpack('I', self.file.read(4))[0]  
        if parameters_off == 0:
            return []
        self.file.seek(parameters_off)  
        parameters_len = struct.unpack('I', self.file.read(4))[0]  
        list_parameters = []
        for i in range(parameters_len):
            parameters_index = struct.unpack('H', self.file.read(2))[0]  
            print("%X -> param %d : %X"%(index, i, parameters_index))
            list_parameters.append(parameters_index)
        return list_parameters


    def parse_fieldids_class(self, index) -> int:
        """
        该函数返回index所对应字段所属的类的typeids索引
        """
        if index > self.fieldIdsSize:
            print("索引%s超过DexField的最大尺寸%s"%(index, self.fieldIdsSize))
            return -1
        offset = self.fieldIdsOff + index * 4 * 2
        self.file.seek(offset)
        class_idx = struct.unpack('H', self.file.read(2))[0]      
        print("DexField %X -> class_idx : %X"%(index, class_idx))
        return class_idx

    def parse_fieldids_type(self, index) -> int:
        """
        该函数返回index所对应字段的类型的typeids索引
        """
        if index > self.fieldIdsSize:
            print("索引%s超过DexField的最大尺寸%s"%(index, self.fieldIdsSize))
            return -1
        offset = self.fieldIdsOff + index * 4 * 2 + 2
        self.file.seek(offset)
        type_idx = struct.unpack('H', self.file.read(2))[0]      
        print("DexField %X -> type_idx : %X"%(index, type_idx))
        return type_idx

    def parse_fieldids_name(self, index) -> int:
        """
        该函数返回index所对应字段的名称的stringids索引
        """
        if index > self.fieldIdsSize:
            print("索引%s超过DexField的最大尺寸%s"%(index, self.fieldIdsSize))
            return -1
        offset = self.fieldIdsOff + index * 4 * 2 + 4
        self.file.seek(offset)
        name_idx = struct.unpack('I', self.file.read(4))[0]      
        print("DexField %X -> name_idx : %X"%(index, name_idx))
        return name_idx


    def parse_methodids_class(self, index) -> int:
        """
        该函数返回index所对应方法所属的类的typeids索引
        """
        if index > self.methodIdsSize:
            print("索引%s超过DexMethod的最大尺寸%s"%(index, self.methodIdsSize))
            return -1
        offset = self.methodIdsOff + index * 4 * 2
        self.file.seek(offset)
        class_idx = struct.unpack('H', self.file.read(2))[0]      
        print("DexMethod %X -> class_idx : %X"%(index, class_idx))
        return class_idx

    def parse_methodids_proto(self, index) -> int:
        """
        该函数返回index所对应方法的声明的protoids索引
        """
        if index > self.methodIdsSize:
            print("索引%s超过DexField的最大尺寸%s"%(index, self.methodIdsSize))
            return -1
        offset = self.methodIdsOff + index * 4 * 2 + 2
        self.file.seek(offset)
        type_idx = struct.unpack('H', self.file.read(2))[0]      
        print("DexMethod %X -> type_idx : %X"%(index, type_idx))
        return type_idx

    def parse_methodids_name(self, index) -> int:
        """
        该函数返回index所对应方法的名称的stringids索引
        """
        if index > self.methodIdsSize:
            print("索引%s超过DexField的最大尺寸%s"%(index, self.methodIdsSize))
            return -1
        offset = self.methodIdsOff + index * 4 * 2 + 4
        self.file.seek(offset)
        name_idx = struct.unpack('I', self.file.read(4))[0]      
        print("DexMethod %X -> name_idx : %X"%(index, name_idx))
        return name_idx    

    def parse_classdef_class(self, index) -> int:
        """
        该函数返回类的类型，指向的是dexTypeids的索引
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 0
        self.file.seek(offset)
        class_idx = struct.unpack('I', self.file.read(4))[0]      
        print("DexClassDef %X -> class_idx : %X"%(index, class_idx))
        return class_idx    

    def parse_classdef_accessFlags(self, index) -> list:
        """
        该函数返回类的访问标志的字符串列表
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 1
        self.file.seek(offset)
        accessFlags = struct.unpack('I', self.file.read(4))[0]
        flags = ACCESS_FLAGS.get_access_flags(accessFlags)  
        print("DexClassDef %X -> accessFlags : %X"%(index, accessFlags))
        print(flags)
        return flags   

    def parse_classdef_superclass(self, index) -> int:
        """
        该函数返回父类的类型，指向的是dexTypeids的索引
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 2
        self.file.seek(offset)
        superclassIdx = struct.unpack('I', self.file.read(4))[0]      
        print("DexClassDef %X -> superclassIdx : %X"%(index, superclassIdx))
        return superclassIdx  

    def parse_classdef_interface(self, index) -> list:
        """
        该函数返回接口的类型的列表，列表内容为dexTypeids的索引
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 3
        self.file.seek(offset)
        interfacesOff = struct.unpack('I', self.file.read(4))[0]      
        print("DexClassDef %X -> interfacesOff : %X"%(index, interfacesOff))
        if interfacesOff == 0:
            return []
        self.file.seek(interfacesOff)  
        interfaces_len = struct.unpack('I', self.file.read(4))[0]  
        list_interfaces = []
        for i in range(interfaces_len):
            interfaces_len_index = struct.unpack('H', self.file.read(2))[0]  
            print("%X -> param %d : %X"%(index, i, interfaces_len_index))
            list_interfaces.append(interfaces_len_index)
        return list_interfaces

    def parse_classdef_source_file(self, index) -> int:
        """
        该函数返回源文件名，指向的是stringids的索引
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 4
        self.file.seek(offset)
        sourceFileIdx = struct.unpack('I', self.file.read(4))[0]      
        print("DexClassDef %X -> sourceFileIdx : %X"%(index, sourceFileIdx))
        return sourceFileIdx 

    def parse_classdef_class_data(self, index) -> list('''list list list list'''):
        """
        return: 返回4个list
                DexField:  [{'fieldIdx': 3526, 'accessFlags': 2}, {'fieldIdx': 1, 'accessFlags': 2}]  
                DexMethod: [{'methodIdx': 7215, 'accessFlags': 65537, 'accecodeOffssFlags': 943708}]
                fieldIdx:指向DexFieldId的索引
                accessFlags由ACCESS_FLAGS类解析
                methodIdx指向DexMethodId的索引
                codeOff:指向DexCode结构的偏移，该结构体中为方法的字节码
        """
        if index > self.classDefsSize:
            print("索引%s超过DexClassDef的最大尺寸%s"%(index, self.classDefsSize))
            return -1
        offset = self.classDefsOff + index * 4 * 8 + 4 * 6
        self.file.seek(offset)
        classDataOff = struct.unpack('I', self.file.read(4))[0]      
        print("DexClassDef %X -> classDataOff : %X"%(index, classDataOff))
        self.file.seek(classDataOff)
        staticFieldsSize = parse_uleb128(self.file)
        instanceFieldsSize = parse_uleb128(self.file)
        directMethodsSize = parse_uleb128(self.file)
        virtualMethodsSize = parse_uleb128(self.file)

        list_staticFields = []
        if (staticFieldsSize != 0):
            dict_static_field = {}
            for i in range(staticFieldsSize):
                dict_static_field["fieldIdx"] = parse_uleb128(self.file)
                dict_static_field["accessFlags"] = parse_uleb128(self.file)
            list_staticFields.append(copy.deepcopy(dict_static_field))
        print(list_staticFields)

        list_instanceFields = []
        if (instanceFieldsSize != 0):
            dict_instance_field = {}
            for i in range(instanceFieldsSize):
                dict_instance_field["fieldIdx"] = parse_uleb128(self.file)
                dict_instance_field["accessFlags"] = parse_uleb128(self.file)
                print("dict_instance_field -> " + str(dict_instance_field))
                list_instanceFields.append(copy.deepcopy(dict_instance_field))
        print(list_instanceFields)

        list_directMethods = []
        if (directMethodsSize != 0):
            dict_direct_method = {}
            for i in range(directMethodsSize):
                dict_direct_method["methodIdx"] = parse_uleb128(self.file)
                dict_direct_method["accessFlags"] = parse_uleb128(self.file)
                dict_direct_method["codeOff"] = parse_uleb128(self.file)
                print("dict_direct_method -> " + str(dict_direct_method))
                list_directMethods.append(copy.deepcopy(dict_direct_method))
        print(list_directMethods)

        list_virtualMethods = []
        if (virtualMethodsSize != 0):
            dict_virtual_method = {}
            for i in range(virtualMethodsSize):
                dict_virtual_method["methodIdx"] = parse_uleb128(self.file)
                dict_virtual_method["accessFlags"] = parse_uleb128(self.file)
                dict_virtual_method["codeOff"] = parse_uleb128(self.file)
                print("dict_direct_method -> " + str(dict_virtual_method))
                list_virtualMethods.append(copy.deepcopy(dict_virtual_method))
        print(list_virtualMethods)

        return  list_staticFields,list_instanceFields,list_directMethods,list_virtualMethods

    def parse_code_item(self, codeOff) ->list('''int'''):
        """
        
        """
        self.file.seek(codeOff)
        registersSize = struct.unpack('H', self.file.read(2))[0]   #使用的寄存器个数
        insSize = struct.unpack('H', self.file.read(2))[0]         #参数个数
        outsSize = struct.unpack('H', self.file.read(2))[0]        #调用其他方法时使用的寄存器个数
        triesSize = struct.unpack('H', self.file.read(2))[0]       #try catch 的个数
        debugInfoOff = struct.unpack('I', self.file.read(4))[0]    #指令调试信息的偏移
        insnsSize = struct.unpack('I', self.file.read(4))[0]       #指令集个数,以2字节为单位
        insns = []
        if insnsSize != 0:
            for i in range(insnsSize * 2):
                ins = struct.unpack('B', self.file.read(1))[0]
                insns.append(ins)
        for i in insns:
            if i < 0x10:
                print("0x0%X"%(i))
            else:
                print("0x%2X"%(i))
        return insns

    def calc_checksum(self) -> int:
        def calculation_var(srcByte,vara,varb): 
            varA = vara
            varB = varb
            icount = 0
            listAB = []
            while icount < len(srcByte):
                varA = (varA + srcByte[icount]) % 65521
                varB = (varB + varA) % 65521
                icount += 1
            listAB.append(varA)
            listAB.append(varB)
            return listAB
        def getCheckSum(varA,varB): 
            Output = (varB << 16) + varA
            return Output
        self.file.seek(0x0c)
        VarA = 1
        VarB = 0
        flag = 0
        CheckSum = 0
        while True:
            srcBytes = []
            for i in range(1024):               #一次只读1024个字节，防止内存占用过大
                ch = self.file.read(1)
                if not ch:                      #如果读取到末尾，设置标识符，然后退出读取循环
                    flag = 1
                    break
                else:
                    ch = binascii.b2a_hex(ch)              #将字节转为int类型，然后添加到数组中
                    ch = str(ch,encoding='utf-8')
                    ch = int(ch,16)
                    srcBytes.append(ch)
            varList = calculation_var(srcBytes,VarA,VarB)
            VarA = varList[0]
            VarB = varList[1]
            if flag == 1:
                CheckSum = getCheckSum(VarA,VarB)
                break
        print('CheckSum = 0x%8X'%(CheckSum)) 


    def calc_signature(self):
        import hashlib
        self.file.seek(0x20)
        sha = hashlib.sha1()
        while True:
            info = self.file.read(1024)
            sha.update(info)
            if not info:
                break
        sha_bytes = sha.digest()
        list_signature = []
        for i in range(sha.digest_size):
            list_signature.append(sha_bytes[i])
        print('signature = 0x%2X 0x%2X 0x%2X 0x%2X'%(sha_bytes[0], sha_bytes[1], sha_bytes[2], sha_bytes[3]))
        print('signature = 0x%2X 0x%2X 0x%2X 0x%2X'%(sha_bytes[4], sha_bytes[5], sha_bytes[6], sha_bytes[7]))
        print('signature = 0x%2X 0x%2X 0x%2X 0x%2X'%(sha_bytes[8], sha_bytes[9], sha_bytes[10], sha_bytes[11]))
        print('signature = 0x%2X 0x%2X 0x%2X 0x%2X'%(sha_bytes[12], sha_bytes[13], sha_bytes[14], sha_bytes[15]))
        print('signature = 0x%2X 0x%2X 0x%2X 0x%2X'%(sha_bytes[16], sha_bytes[17], sha_bytes[18], sha_bytes[19]))
        return list_signature
#*****************************************************************************************
def update_dex(path, list_bytes, addr, size):
    """
    param:path要修改的dex文件路径, list_bytes要写入的字节数组, addr写入的地址, size写入的字节数
    """
    with open(path, 'rb', True) as files:
        barray = bytearray(files.read())
    for i in range(size):
        barray[addr + i] = list_bytes[i]
    with open(path, 'wb', True) as files:
        files.write(barray)

#*****************************************************************************************

def int_to_bytes(value) -> list:
    list_bytes = []
    for i in range(4):
        tmp = value >> 8 * i
        tmp = tmp & 0xFF
        print("0x%2x"%(tmp))
        list_bytes.append(tmp)
    return list_bytes



#*****************************************************************************************

def parse_dex_file(path:str):
    """
    function: 
    """ 
    if not os.path.exists(path):
        return
    with open(path, 'rb', True) as files:
        print(files)
        dex_header = Dex_Parse(files)
        dex_header.calc_checksum()
        dex_header.calc_signature()
        dex_header.parse_stringids_index(1727)
        dex_header.parse_typeids_index(0)
        dex_header.parse_protoids_shorty(408)
        dex_header.parse_protoids_return_type(408)
        dex_header.parse_protoids_parameters(408)
        dex_header.parse_fieldids_class(0)
        dex_header.parse_fieldids_type(0)
        dex_header.parse_fieldids_name(0)
        dex_header.parse_methodids_class(5)
        dex_header.parse_methodids_proto(5)
        dex_header.parse_methodids_name(5)
        dex_header.parse_classdef_class(0)
        dex_header.parse_classdef_accessFlags(0)
        dex_header.parse_classdef_superclass(0)
        dex_header.parse_classdef_interface(0)
        dex_header.parse_classdef_source_file(0)
        print("***************************************************************************")
        list_staticFields,list_instanceFields,list_directMethods,list_virtualMethods = dex_header.parse_classdef_class_data(255)
        if list_virtualMethods:
            methodIdx = 0
            for virtualMethods in list_virtualMethods:
                methodIdx = virtualMethods['methodIdx'] + methodIdx
                accessFlags = virtualMethods['accessFlags']
                codeOff = virtualMethods['codeOff']
                classIdx = dex_header.parse_methodids_class(methodIdx)
                descriptorIdx = dex_header.parse_typeids_index(classIdx)
                str_class = dex_header.parse_stringids_index(descriptorIdx)
                print("class -> " + str_class)
                nameIdx = dex_header.parse_methodids_name(methodIdx)
                str_method = dex_header.parse_stringids_index(nameIdx)
                print("method -> " + str_method)
                protoIdx = dex_header.parse_methodids_proto(methodIdx)
                shortyIdx = dex_header.parse_protoids_shorty(protoIdx)
                str_proto = dex_header.parse_stringids_index(shortyIdx)
                print("proto -> " + str_proto)
                print("ACCESS_FLAGS -> " + str(ACCESS_FLAGS.get_access_flags(accessFlags)))
                dex_header.parse_code_item(codeOff)
                print("***************************************************************************")
        #dex_header.parse_code_item(0xE65BC)
        print("***************************************************************************")

    

#*****************************************************************************************

if __name__ == '__main__': 
    #int_to_bytes(656993846)
    filename = './classes.dex'
    mDexHeader = parse_dex_file(filename)
    update_dex('./classes.dex', [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19], 0xC, 20) # 更改signature






