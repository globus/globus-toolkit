#!/bin/sh

wd=`pwd`
if [ -f ../sh_util/Makefile.in ] ; then
	cd ..
fi
for f in ncftp libncftp sh_util vis sio Strn ; do
	if [ ! -f "$f" ] && [ ! -d "$f" ] ; then
		echo "Missing directory $f ?" 1>&2
		exit 1
	fi
done

TMPDIR=/tmp
if [ "$#" -lt 2 ] ; then
	TARDIR="ncftp"
	STGZFILE="$TARDIR.tar.gz"
else
	TARDIR="$1"
	STGZFILE="$2"
fi

rm -rf $TMPDIR/TAR
mkdir -p -m755 $TMPDIR/TAR/$TARDIR 2>/dev/null

chmod 755 configure sh/* install-sh
find . -name '*.[ch]' -exec sh/dos2unix.sh {} \;
find . -name '*.in' -exec sh/dos2unix.sh {} \;

if [ -f "$wd/sh/fixfcase.sh" ] ; then
	$wd/sh/fixfcase.sh "$wd"
fi

find . -depth -follow -type f | sed '
/\/samples/d
/libncftp\/configure$/d
/sio\/configure$/d
/Strn\/configure$/d
/\.o$/d
/\.so$/d
/\.a$/d
/\.lib$/d
/\.ncb$/d
/\.pdb$/d
/\.idb$/d
/\.pch$/d
/\.ilk$/d
/\.res$/d
/\.opt$/d
/\.plg$/d
/\.obj$/d
/\.exe$/d
/\.zip$/d
/\.gz$/d
/\.tar$/d
/\.swp$/d
/\.orig$/d
/\.rej$/d
/\/Makefile\.bin$/p
/\.bin$/d
/\/bin/d
/\/core$/d
/\/^[Rr]elease$/d
/\/^[Dd]ebug$/d
/\/sio\/.*\//d
/shit/d
/\/upload/d
/\/config\.h\.in$/p
/\/config\./d
/\/Makefile$/d
/\/OLD/d
/\/old/d' | cut -c3- | tee "$wd/doc/manifest" | cpio -Lpdm $TMPDIR/TAR/$TARDIR

if [ -f "$wd/sh/unix2dos.sh" ] ; then
	cp "$wd/doc/manifest" "$wd/doc/manifest.txt" 
	$wd/sh/unix2dos.sh "$wd/doc/manifest.txt"
fi

( cd $TMPDIR/TAR ; tar cvf - $TARDIR | gzip -c > $STGZFILE )
cp $TMPDIR/TAR/$STGZFILE .
chmod 644 $STGZFILE
rm -rf $TMPDIR/TAR
ls -l $STGZFILE 2>/dev/null
mv $TGZFILE newbin/ 2>/dev/null
exit 0
