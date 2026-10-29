#!/bin/bash
# Read-only snapshot of CTRL01's data directory (sqlite backup API + datasets + models)
set -e
SP=${SP:-$(pwd)}  # snapshot lands in $SP/afwdata
DEST=$SP/afwdata
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo rm -rf /tmp/afwsnap && sudo mkdir -p /tmp/afwsnap &&
 sudo -u afwctl /opt/afw/venv/bin/python -c "import sqlite3;s=sqlite3.connect(\"/var/lib/afw/afw.sqlite3\");d=sqlite3.connect(\"/tmp/afwsnap-db.sqlite3\");s.backup(d);d.close()" 2>/dev/null || sudo /opt/afw/venv/bin/python -c "import sqlite3;s=sqlite3.connect(\"/var/lib/afw/afw.sqlite3\");d=sqlite3.connect(\"/tmp/afwsnap/afw.sqlite3\");s.backup(d);d.close()"
 [ -f /tmp/afwsnap-db.sqlite3 ] && sudo mv /tmp/afwsnap-db.sqlite3 /tmp/afwsnap/afw.sqlite3
 sudo tar -C /var/lib/afw -cf /tmp/afwsnap/data.tar datasets models && sudo chmod -R a+r /tmp/afwsnap'
rm -rf $DEST.new && mkdir -p $DEST.new
scp -q -F ~/.config/afw/ssh_config ctrl01:/tmp/afwsnap/afw.sqlite3 $DEST.new/
scp -q -F ~/.config/afw/ssh_config ctrl01:/tmp/afwsnap/data.tar $DEST.new/
tar -C $DEST.new -xf $DEST.new/data.tar && rm $DEST.new/data.tar
rm -rf $DEST.old; [ -d $DEST ] && mv $DEST $DEST.old; mv $DEST.new $DEST
ssh -F ~/.config/afw/ssh_config ctrl01 'sudo rm -rf /tmp/afwsnap'
ls $DEST/datasets | tr '\n' ' '
