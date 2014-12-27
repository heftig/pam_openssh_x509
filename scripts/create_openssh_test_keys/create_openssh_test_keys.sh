#!/bin/bash

CAT='/usr/bin/cat'
MV='/usr/bin/mv'
RM='/usr/bin/rm'
SED='/usr/bin/sed'
OPENSSL='/usr/bin/openssl'
SSHKEYGEN='/usr/bin/ssh-keygen'
TMPDIR='openssh_keys_temp'
DSTDIR='openssh_keys'
ONELINER='ssh_rsa.txt'
AMOUNT=1948

mkdir $TMPDIR
rm -rf $DSTDIR
mkdir $DSTDIR
for i in $(seq 0 $AMOUNT)
do
	FILENAME="ssh_$i"
	$SSHKEYGEN -C "" -P "" -f $TMPDIR/$FILENAME
	echo -n "ssh_$i.pem:" >> $ONELINER
	$OPENSSL rsa -in $TMPDIR/$FILENAME -pubout -out $TMPDIR/$FILENAME.pem
	$CAT $TMPDIR/${FILENAME}.pub | $SED 's/ *$//' >> $ONELINER
done

$MV $TMPDIR/*.pem $DSTDIR
$MV $ONELINER $DSTDIR
$RM -rf $TMPDIR

