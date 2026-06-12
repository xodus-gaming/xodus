#!/bin/bash
set -eu

if [ "`whoami`" != "root" ]; then
    echo Needs to be run as root!
    exit 1
fi

dd if=/dev/zero of=testfs1 bs=1k count=2048
mkntfs -c 512 -L mylabel -F testfs1

mkdir mnt
mount -t ntfs-3g -o loop testfs1 mnt
cd mnt

# Create a file with a specific modification time that we can check.
touch -m -t 202101011337 empty-file

# Create a 5-bytes file with resident data.
echo -n 12345 > file-with-12345

# Create a 1000-bytes file with non-resident data.
for i in {1..200}; do
    echo -n 12345 >> 1000-bytes-file
done

# Create a sparse file with data at the beginning and at the end.
echo -n 12345 > sparse-file
tr '\0' '1' < /dev/zero | dd of=sparse-file seek=500000 bs=1 count=5

# Create so many directories that the filesystem needs an INDEX_ROOT and INDEX_ALLOCATION.
mkdir many_subdirs
cd many_subdirs
for i in {1..512}; do
    mkdir $i
done
cd ..

cd ..
umount mnt
rmdir mnt
