def decode_access_mask(mask):
    access_rights = {
        0x00010000: "DELETE",
        0x00020000: "READ_CONTROL",
        0x00040000: "WRITE_DAC",
        0x00080000: "WRITE_OWNER",
        0x00100000: "SYNCHRONIZE",
        0x00000001: "FILE_READ_DATA",
        0x00000002: "FILE_WRITE_DATA",
        0x00000004: "FILE_APPEND_DATA",
        0x00000008: "FILE_READ_EA",
        0x00000010: "FILE_WRITE_EA",
        0x00000020: "FILE_EXECUTE",
        0x00000040: "FILE_DELETE_CHILD",
        0x00000080: "FILE_READ_ATTRIBUTES",
        0x00000100: "FILE_WRITE_ATTRIBUTES",
        0x00020000: "STANDARD_RIGHTS_READ",
        0x00020000: "STANDARD_RIGHTS_WRITE",
        0x00020000: "STANDARD_RIGHTS_EXECUTE",
        0x001f0000: "STANDARD_RIGHTS_ALL",
        0x10000000: "GENERIC_ALL",
        0x20000000: "GENERIC_EXECUTE",
        0x40000000: "GENERIC_WRITE",
        0x80000000: "GENERIC_READ",
    }

    if isinstance(mask, str):
        mask = int(mask, 16)

    associated_rights = []
    for value, name in access_rights.items():
        if mask & value:
            associated_rights.append(name)

    return associated_rights

mask = input("Access Mask: ")
rights = decode_access_mask(mask)

print("Rights associated with the mask:")
for right in rights:
    print(f"- {right}")