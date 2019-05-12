#!/bin/sh

### MySQL Connection Params ###
MYSQLU="root"
MYSQLP="hackme"
MYSQLS="localhost"

### FTP Connection params ###
FTPD="/my_backups_folder"
FTPU="user123"
FTPP="hackme"
FTPS="ftp.example.com"

### Binaries ###
TAR="$(which tar)"
FTP="$(which ftp)"
MYSQL="$(which mysql)"
MYSQLDUMP="$(which mysqldump)"
GZIP="$(which gzip)"

### Check if FTP is installed
if [ -z "${FTP}" ]; then
    apt-get update
    apt-get install ftp
fi

## Time format YYYYMMDDHHIISS ###
NOW=$(date +%Y-%m-%d_%H-%M-%S)

### Temporary backup directory ###
TMP_BACKUP_DIR=/tmp/backup$NOW
mkdir $TMP_BACKUP_DIR

dpkg --get-selections "*" > $TMP_BACKUP_DIR/my-dpkg-selections.txt

### Backup itself ###
# Examples #
cd /etc && $TAR -czpf $TMP_BACKUP_DIR/my-etc.tgz *
cd /var/lib/dpkg && $TAR -czpf $TMP_BACKUP_DIR/my-var-lib-dpkg.tgz *
cd /var/www && $TAR -czpvf $TMP_BACKUP_DIR/www.tgz --exclude=*/.git/* --exclude=*/cache/* --exclude=*/tmp/* *
cd /var/log && $TAR -czpf $TMP_BACKUP_DIR/my-var-log.tgz *
cd /root && $TAR -czpf $TMP_BACKUP_DIR/root.tgz *

### MySQL ###
FILEDIR="$TMP_BACKUP_DIR/my-databases"
mkdir "$FILEDIR"
DATABASES="$($MYSQL -u$MYSQLU -h $MYSQLS -p$MYSQLP -Bse 'show databases;')"
for db in $DATABASES
  do
    FILE="$FILEDIR/$db.sql.gz"
    $MYSQLDUMP --add-drop-table --allow-keywords -q -c -u "$MYSQLU" -h "$MYSQLS" -p$MYSQLP "$db" $i | $GZIP -9 > "$FILE"
done


### Now collect everything into one archive ###
ARCHIVE=`hostname`_$NOW.tgz
cd $TMP_BACKUP_DIR && $TAR -czf $TMP_BACKUP_DIR/$ARCHIVE --exclude=$ARCHIVE *

### Upload to FTP ###
cd $TMP_BACKUP_DIR
$FTP -n $FTPS <<END_SCRIPT
quote USER $FTPU
quote PASS $FTPP
cd $FTPD
mput $ARCHIVE
quit
END_SCRIPT

### Clean ###
rm -rf $TMP_BACKUP_DIR

echo ""
