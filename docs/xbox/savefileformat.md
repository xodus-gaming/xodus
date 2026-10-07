All values are little endian unless specified otherwise.
Strings are represented their length(DWORD) followed by the LE UTF-16 string with no null terminator.
GUIDs are represented in mixed byte order. The first three values are little endian. The last two are big endian.
For example, `01020304-0506-0708-090A-0B0C0D0E0F10` is represented as `0403020106050807090A0B0C0D0E0F10`.

### containers.index
#### Metadata
`container.index` starts with the following metadata:
```
DWORD version (currently 14)
DWORD entryCount
STRING unknown (Initialized empty but existing values are preserved.)
STRING AUMID (Application User Model ID)
QWORD Last modified or synced file time
DWORD sync flags
STRING ownerChangedID
QWORD storage quota
```
#### Entry
The metadata is followed by one entry for each container in alphabetical order.
```
STRING containerName
STRING containerDisplayName
STRING etag
BYTE container number
DWORD syncState
GUID container GUID
DWORD FILETIME lastModifiedTime
DWORD unknown flags
(only the lowest order flag has been observed to change. The others are preserved.)
DWORD unknown (set to zero)
QWORD totalSize
```
#### Sync states
Together with ETags, sync states are used to identify changes and conflicts.
If a container has been modified and the ETag doesn't match, the
user is asked which save they would like to keep.
If two clients modify different containers, the saves are merged without
triggering a conflict.
```
0 offline
1 synced
2 modified
3 deleted
4
5 created
```
Value 4 causes the entry to be ignored. It has not yet been observed in real
saves. Is it used during conflict resolution?

#### Sync flags
```
1 All containers are uploaded.
2 All containers are downloaded.
16 has been observed during conflicts but not always.
```

### container.n
The container number increases by one each time the container is modified
until it reaches 255. After 255 it is reset to 0.
#### Metadata
```
DWORD version (currently 4)
DWORD blobCount
```
#### Entry
```
128 bytes UTF-16 blobName
GUID last synced atom
GUID current atom
```

### Naming rules
Container names may have length up to 256.<br />
Container names may include `0123456789/abcdefghijklmnopqrstuvwxyz.-ABCDEFGHIJKLMNOPQRSTUVWXYZ`.<br />
Container names may not contain `\\`.<br />
Container names may not start with `/`.<br />
Container names may not end with `/`.<br />
Container names may not end with `.`.<br />
Container names may not contain two consecutive `/`.<br />
Container names may not contain two consecutive `.`.<br />
Container names may not contain a `.` before the final `/`.<br />
Container names may not contain a `-` before the final `/`.<br />
UTF-8 null-terminated representation of blob names must have size less than 66.

### Example directory layout
```
.
├── containers.index
├── <container1 UUID>/
│   └── contianer.<container1 number>
└── <container2 UUID>/
    ├── <atom1 UUID>
    ├── <atom2 UUID>
    └── container.<container2 number>
```
### Example Files
container.0
```
00000000: 0400 0000 0200 0000 6200 6c00 6f00 6200  ........b.l.o.b.
00000010: 4e00 6100 6d00 6500 0000 0000 0000 0000  N.a.m.e.........
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000070: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000080: 0000 0000 0000 0000 8597 926c 3626 5cab  ...............M
00000090: aa68 2a74 6800 8616 8597 926c 3626 5cab  ._U............M
000000a0: aa68 2a74 6800 8616 6200 6c00 6f00 6200  ._U.....b.l.o.b.
000000b0: 4e00 6100 6d00 6500 3100 0000 0000 0000  N.a.m.e.1.......
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000110: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000120: 0000 0000 0000 0000 351a 6114 baac c6d0  ........X.|R..gJ
00000130: 437b 039b b460 24fe 4cee 12de 6044 4e10  ...p.........1}O
00000140: 3e7b eefe abe0 4b05                      ......`.
```
containers.index
```
00000000: 0e00 0000 0000 0000 0000 0000 1000 0000  ................
00000010: 3c00 3c00 5000 5200 4f00 4300 4500 5300  <.<.P.R.O.C.E.S.
00000020: 5300 5f00 3300 3100 3100 3600 3e00 3e00  S._.3.1.1.6.>.>.
00000030: 0000 0000 0000 0000 0100 0000 2400 0000  ............$...
00000040: 3000 3000 3000 3000 3000 3000 3000 3000  0.0.0.0.0.0.0.0.
00000050: 2d00 3000 3000 3000 3000 2d00 3000 3000  -.0.0.0.0.-.0.0.
00000060: 3000 3000 2d00 3000 3000 3000 3000 2d00  0.0.-.0.0.0.0.-.
00000070: 3000 3000 3000 3000 3000 3000 3000 3000  0.0.0.0.0.0.0.0.
00000080: 3000 3000 3000 3000 0000 0000 0000 0000  0.0.0.0.........
```

### See also
[titlestorage](./titlestorage.md)

