#! /bin/sh
TAR_DATE=`date +%Y%m%d`
echo $TAR_DATE
TAR_FILE="unhide-$TAR_DATE"
echo $TAR_FILE

if [ -e "../$TAR_FILE" ]; then
   echo "../$TAR_FILE already exists, do you want to delete it and continue [yN] ?"
   read DEL_DIR
   if [ $DEL_DIR == "Y" -o  $DEL_DIR == "y" ]; then
      if [ -d "../$TAR_FILE" ]; then
         echo "\rm -rf ../$TAR_FILE"
      else
         echo "\rm -f ../$TAR_FILE"
      fi
   else
      exit 1
   fi
else
   echo "../$TAR_FILE n'existe pas"
fi   
mkdir -p ../$TAR_FILE/man/es ../$TAR_FILE/man/fr
for FILE in `cat tar_list.txt`; do
   cp $FILE ../$TAR_FILE/$FILE
done 
tar -czvf $TAR_FILE.tgz ../$TAR_FILE
mv $TAR_FILE.tgz ../$TAR_FILE
