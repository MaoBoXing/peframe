# -*- coding: utf-8 -*- #
try:
    import re,sys,string,os,math,time,datetime,subprocess,hashlib,inspect
except Exception as e:
    print(e)
pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
sys.path.append(pathname+"/modules")
try:
    import pefile
    import peutils
except ImportError as e:
    print("部署你的环境 {}".format(e))
    
def HELP():
    txt = """
代码具体使用方法如下:
    python3 PE_Check.py [--选项] [样本名]
选项列表：
    -h  或者 --help ， 可弹出帮助选项
    -a  或者 --auto ， 输出默认分析结果
    -i  或者 --info ， 输出文件信息
    --hash          ， 输出文件的hash加密值
    --meta          ， 输出程序的产品信息
    --peid          ， 输出文件标识
    --antivm        ， 输出反虚拟机检查
    --antidbg       ， 输出反调试函数检查
    --sections      ， 输出节区信息，并通过熵值分辨节区是否可疑
    --funcimport    ， 输出导入动态链接库列表 
    --strings       ， 输出存在的字符串
    --url           ， 对样本中涉及的文件和网址进行检测
    --suspicious    ， 输出可疑导入函数、可疑反调试函数、可疑节区
    --dump          ， 输出各个区块的简要信息
    --hexdump       ， 将所有数据，以hexdump的方式输出
    --import        ， 输出导入表
    --export        ， 输出导出表
    --resource      ， 输出资源表
    --debug         ， 输出调试节区信息
"""
    print(txt)       
def HASH():
    fh = open (exename,'rb')
    m = hashlib.md5()
    s = hashlib.sha1()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
        s.update(data)
    print("MD5   hash:\t",m.hexdigest())
    print("SHA-1 hash:\t",s.hexdigest())
    
def INFO():
    print("文件名：\t",os.path.basename(exename))
    print("文件大小：\t",os.path.getsize(exename),"byte")
    # print("Optional Header:\t\t",hex(pe.OPTIONAL_HEADER.ImageBase))
    # print("Address Of Entry Point:\t\t",hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    print("创建时间:\t",datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp))
    # print("Subsystem:\t\t\t",pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem])
    # machine=0
    # machine = pe.FILE_HEADER.Machine
    # print("Required CPU type:\t\t",pefile.MACHINE_TYPE[machine])
    # print("Number of RVA and Sizes: \t",pe.OPTIONAL_.NumberOfRvaAndSizes)
    dll = pe.FILE_HEADER.IMAGE_FILE_DLL
    print("是否为DLL文件:\t",dll)
    print("数据节区数量:\t",pe.FILE_HEADER.NumberOfSections)

def convert_char(char):
    if (char in string.ascii_letters)or(char in string.digits)or(char in string.punctuation)or(char in string.whitespace):
        return char
    else:
        return (r'\x%02x'% ord(char))
def convert_to_printables(s):
    return ''.join([convert_char(c) for c in s])
def META():
    ret =[]
    if hasattr(pe,'VS_VERSIONINFO'):
        if hasattr(pe,'FileInfo'):
            # print (pe.FileInfo)
            # print(pe.)
            for finfo in pe.FileInfo:
                for entry in finfo:
                    if hasattr(entry,'StringTable'):
                        # print(entry.StringTable)
                        for st_entry in entry.StringTable:
                            for key, vue in list(st_entry.entries.items()):
                                # ret.append(convert_to_printables(str_entry[0]) + ':' + convert_to_printables(str_entry[1]))
                                print(key.decode("utf-8")+ "\t\t:" + vue.decode("utf-8"))
                    elif hasattr(entry,'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry,'entry'):
                                print(list(var_entry.entry.keys())[0].decode("utf-8")+'\t\t:'+list(var_entry.entry.values())[0])
                                # ret.append(convert_to_printables(var_entry.entry.keys()[0])+':'+convert_to_printables(var_entry.entry.values()[0]))


# STRINGS 函数
printable = set(string.printable)      
def process(stream):
    found_str = ""
    # print(printable)
    while True:
        data = stream.read(1024*4)
        # print(data)
        if not data:
            break
        for char in data:
            try:
                if (char>=32) and (char<=126):
                    found_str += chr(char)
                elif len(found_str) > 5 and len(found_str) < 70:
                    yield found_str
                    found_str = ''
                else:
                    found_str =''
            except Exception as e:
                print(e)
                print(found_str)
                print(char)
                exit()
def STRINGS():
    PEtoStr = open(exename,'rb')
    for found_str in process(PEtoStr):
        print(found_str)
    PEtoStr.close()

#section analyzer
def SECTIONS():
    print("节区数量：",pe.FILE_HEADER.NumberOfSections)
    print
    print("节区名\t虚拟地址\t\t虚拟内存大小\t\t磁盘存储大小\t节区是否可疑")
    for section in pe.sections:
        section.get_entropy()
        if section.SizeOfRawData == 0 or (section.get_entropy()>0 and section.get_entropy()<1) or section.get_entropy()>7:  #根据
            suspicious = "YES"
        else:
            suspicious = "NO"
        if len(section.Name) < 7:
            seqName="\t\t"
        else:
            seqName="\t"
        if len(hex(section.VirtualAddress)):
            seqVA="\t\t"
        else:
            seqVA="\t"
        if len(hex(section.Misc_VirtualSize)):
            seqVS="\t\t"
        else:
            seqVS="\t"
        if len(str(section.SizeOfRawData))<7:
            seqSD="\t\t"
        else:
            seqSD="\t"
            
        print(section.Name.decode("utf-8"),seqName,hex(section.VirtualAddress),seqVA,hex(section.Misc_VirtualSize),seqVS,section.SizeOfRawData,seqSD,suspicious)
        print("MD5值    :",section.get_hash_md5())
        print("SHA-1值    :",section.get_hash_sha1())
        # print("SHA-256值:",section.get_hash_sha256())
        # print("SHA-512值:",section.get_hash_sha512())
            

#PEID壳检测函数
def PEID():
    try:
        signatures = peutils.SignatureDatabase(pathname + "/modules/userdb.txt")        #该配置文件必须是gbk编码
        matchs = signatures.match_all(pe,ep_only=True)
        print("文件标识: \t\t",matchs[0][0])
    except Exception as e:
        print(e)
#CHECKANTIVM 反虚拟机功能检测
def CHECKANTIVM():
    try:
        VM_Sign = {
            "Red Pill":b"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
            "VirtualPc trick":b"\x0f\x3f\x07\x0b",
            "VMware trick":b"VMXh",
            "VMCheck.dll":b"\x45\xC7\x00\x01",
            "VMCheck.dll for VirtualPC":b"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
            "Xen":b"XenVMM",
            "Bochs & QEmu CPUID Trick":b"\x44\x4d\x41\x63",
            "Torpig VMM Trick": b"\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
            "Torpig (UPX) VMM Trick": b"\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
            }
        CountTricks=0
        with open(exename,"rb") as f:
            buf = f.read()
            for trick in VM_Sign:
                if buf.find(VM_Sign[trick][::-1]) >-1:
                    print("Ati VM:\t",trick)
                    CountTricks = CountTricks + 1
        if CountTricks == 0:
            print("Anti VM:\tNone")
    except Exception as e:
        print(e)
# URL检测
def URL():
    PEtostr = open(exename,'rb')
    array = []
    arrayURL = []
    arrayFILE = []

    for found_str in process(PEtostr):
        fname = re.findall("(.+\.([a-z]{2,3}$))+",found_str,re.IGNORECASE | re.MULTILINE)
        if fname:
            word = fname[0][0]
            array.append(word)
    for elem in sorted(array):
        match = re.search("http|www|.com$|.org$|.it$|.co.uk$|.ru$|.jp$|.net$|.ly$|.gl$|^([0-9]{1,3})(?:\.[0-9]{1,3}){3}$",elem,re.IGNORECASE)
        if match:
            arrayURL.append(elem)
        else:
            arrayFILE.append(elem)
    for elem in sorted(set(arrayFILE)):
        match = re.search(".dat$|.bin$|.zip$|.tmp$|.ocx$|.pdf$|.mp3$|.jpg$|.rar$|.exe$|.wmv$|.doc$|.avi$|.ppt$|.mpg$|.tif$|.wav$|.mov$|.psd$|.wmaxls$|.mp4$|.txt$|.bmp$|.ppspub$|.dwg$|.gifmpegswf$|.asf$|.png$|.dat$|jar$|.iso$|.flv7z$|.gz$|.rtf$|.msi$|.jpeg$|.3gp$|html$|.pst$|.cab$|.bin$|.tgz$|.tar$|.log$|.dll$|eml$|.ram$|.lnk$|.bat$|.asx$|.sql$|.asp$|.aspx$|.php$",elem,re.IGNORECASE)
        if match:
            print("文件:\t\t",elem)
        else:
            if opt == '--file-verbose':
                print("???:\t\t",elem)
    if not opt == '--file-verbose':
        for elem in sorted(set(arrayURL)):
            print("URL:\t\t",elem)
    PEtostr.close()


#IMPORT函数查询导入地址表

def IMPORT():
    try:
        print(pe.DIRECTORY_ENTRY_IMPORT[0].struct)
    except Exception as e:
        try:
            print(pe.DIRECTORY_ENTRY_IMPORT.struct)
        except:
            print("NONE")        


def EXPORT():
    try:
        print(pe.DIRECTORY_ENTRY_EXPORT[0].struct)
    except Exception as e:
        try:
            print(pe.DIRECTORY_ENTRY_EXPORT.struct)    
        except Exception as e:
            print("NONE")          
            
def RESOURCE():
    try:
        print(pe.DIRECTORY_ENTRY_RESOURCE[0].struct)
    except:       
        try:
            print(pe.DIRECTORY_ENTRY_RESOURCE.struct)
        except:
            print("NONE")
def DEBUG():
    try:
        print(pe.DIRECTORY_ENTRY_DEBUG[0].struct)
    except:       
        try:
            print(pe.DIRECTORY_ENTRY_DEBUG.struct)
        except:
            print("NONE")
#Functions
def FUNCIMPORT():
    array = []
    library = []
    libdict = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll
            for imp in entry.imports:
                address = hex(imp.address)
                function = imp.name
                
                if dll not in library:
                    library.append(dll)
                array.append({"library": dll, "address": address, "function": function})

        
        for key in library:
            libdict[key] = []
        
        for lib in library:
            for item in array:
                if lib == item['library']:
                    libdict[lib].append({"address": item['address'], "function": item['function']})
    except:
        pass
    print("导入的动态链接库有：")
    # print(libdict)
    for dll in library:
        print("\t",dll.decode())


def SUSPICIOUS():
    print("该样本调用了可疑的接口函数:")
    APIALERT()
    print("\n可疑的反调试接口函数:")
    APIANTIDBG(0)
    print("\n可疑的节区:")
    SECTIONSALERT()
    

def APIALERT():
    file_alerts = open(pathname+"/modules/alerts.txt","r")
    alerts = file_alerts.readlines()
    # print(alerts)
    file_alerts.close()
    array = []
    dbgarray = []
    if not hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        print("没发现可疑的API")
    else:
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != None)and(imp.name!=""):
                    for alert in alerts:
                        # print(imp.name)
                        # print(str(imp.name))
                        # print(alert)
                        if str(imp.name,encoding="utf-8").startswith(alert.strip()):
                            array.append(imp.name)
    if array:
        for elemn in  sorted(set(array)):
            print("函数名：\t",elemn)

def APIANTIDBG(out):
    anti_dbgs_file = open(pathname+"/modules/antidbg.txt","r")
    anti_dbgs = anti_dbgs_file.readlines()
    countantidbg = 0
    if not hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
        print("没发现可疑的反调试接口函数")
    else:
        for lib in pe.DIRECTORY_ENTRY_IMPORT:        
            for imp in lib.imports:
                # print(imp.name)
                if (imp.name != None)and(imp.name != ''):
                    # print(imp.name)
                    for anti_dbg in anti_dbgs:
                        if str(imp.name).startswith(anti_dbg):
                            if out == 1:
                                print("反调试接口:\t",imp.name)
                            else:
                                countantidbg = countantidbg + 1
    if out == 0:
        if countantidbg >0:
            print("反调试接口: \tYES")
        else:
            print("反调试接口：\tNone")

def SECTIONSALERT():
    for section in pe.sections:
        section.get_entropy()
        if section.SizeOfRawData == 0 or ((section.get_entropy() > 0) and (section.get_entropy() < 1)) or section.get_entropy()>7:
             print("Sect . Name:\t",section.Name.decode("utf8"))
             print("MD5    hash:\t",section.get_hash_md5())
             print("SHA-1  hash:\t",section.get_hash_sha1())
    


def DUMP():
    print(pe.dump_info())

def ascii(x):
    if 32<=x<=126:
        return chr(x)
    elif 160<=x<=255:
        return '.'
    else:
        return '.'
    
def HEXDUMP(width=16 , verbose=0 , start=0 ):
    try:
        pos = 0
        f = open(exename,"rb")
        ascmap=[ascii(x) for x in range(256)]
        lastbuf = ''
        lastline=''
        nStartLen=0
        if width>4:
            spaceCol = width/2
        else:
            spaceCol = -1
        hexwidth = 3*width
        if spaceCol != -1:
            hexwidth += 1
        

        if start:
            f.seek(start)
        while 1:
            buf = f.read(width)
            length = len(buf)
            if length == 0:
                if nStartLen:
                    if nStartLen >1:
                        print("* %d"%(nStartLen-1))
                    print(lastline)
                return
            bShowBuf = 1

            if not verbose and buf==lastbuf:
                nStartLen +=1
                bShowBuf = 0
            else:
                if nStartLen:
                    if nStartLen ==1:
                        print(lastline)
                    else:
                        print("%d"%nStartLen)
                nStartLen = 0
                
            hex = ''
            asc = ''
            for i in range(length):
                c = buf[i]
                if i == spaceCol:
                    hex = hex +' '
                hex = hex + ("%02x"% c) + " "
                asc =  asc +ascmap[c]
            line = "%06x: %-*s %s"%(pos,hexwidth,hex,asc)
            
            if bShowBuf:
                print(line)
            pos = pos + length
            lastbuf = buf
            lastline = line
        f.close()
    except Exception as e:
        print(e)
    
        
# main函数开始
if len(sys.argv)<3:
    HELP()
    sys.exit
elif len(sys.argv)==3:
    opt = sys.argv[1]
    exename = sys.argv[2]
    try:
        print(opt)
        pe = pefile.PE(exename)
        if (opt == '-h') or (opt == '--help'):
            HELP()
        elif (opt == '-a') or (opt =='--auto'):
            INFO()
            HASH()
            try:
                PEID()
            except Exception as e:
                print(e)
                print("None")
            APIANTIDBG(0)
            try:
                CHECKANTIVM()
            except Exception as e:
                print("Anti VM:\tError")
            print
            print("File and URL")
            URL()
            print
            SUSPICIOUS()
            print()
            META()
        elif opt == '--hash':
            HASH()
        elif (opt == '-i') or(opt == '--info'):
            INFO()
        elif opt == '--meta':
            META()
        elif opt == '--peid':
            try:
                PEID()
            except Exception as e:
                print("None")
        elif opt == '--antivm':
            try:
                CHECKANTIVM()
            except Exception as e:
                print(e)
                print('Anti VM:\tError')
        elif opt == '--antidbg':
            APIANTIDBG(0)
        elif opt == '--sections':
            SECTIONS()
        elif opt == '--funcimport':
            FUNCIMPORT()
        elif opt == '--strings':
            STRINGS()
        elif opt == '--url':
            URL()
        elif opt == '--suspicious':
            SUSPICIOUS()
        elif opt == '--dump':
            DUMP()
        elif opt == '--hexdump':
            HEXDUMP()
        elif opt == '--import':
            IMPORT()
        elif opt == '--export':
            EXPORT()
        elif opt == '--resource':
            RESOURCE()
        elif opt == '--debug':
            DEBUG()
        else:
            HELP()
            sys.exit                
    except Exception as e:
        print(e)
        print("No Portable Executable")
        sys.exit
else:
    exename = sys.argv[1]
    if exename == "--help":
        HELP()
        sys.exit
        
 