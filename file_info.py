import pefile

exe_path = "C:\Users\Funani Ndou\Desktop\HIT 400 TINGZ\HIT 400 CODE\heroku-cli-x64.exe"
pe = pefile.PE(exe_path)

# print("[*] e_magic value: %s" % hex(pe.DOS_HEADER.e_magic))
# print("[*] Signature value: %s" % hex(pe.NT_HEADERS.Signature))


# print (pe.FileInfo)


def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


data = get_version_info(pe)

print(data)


print("[*] Listing imported DLLs...")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print('\t' + entry.dll.decode('utf-8'))