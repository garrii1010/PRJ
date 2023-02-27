# !/bin/bash

SQL_HOST=localhost
SQL_USER="DBgod"
SQL_PASSWORD="dbGOD"
SQL_DATABASE="DBusb"
SQL_ARGS="-h $SQL_HOST -u $SQL_USER -p$SQL_PASSWORD -D $SQL_DATABASE -s -e"
for (( ; ; ));
do

    a=0
    sleep 1
    for i in $(ls /dev/sd*)
	    do
            if [ $i != "/dev/sda" ] && [ $i != "/dev/sda1" ] && [ $i != "/dev/sda2" ] && [ $i != "/dev/sda3" ];
                then
                    a=$(echo $i)
                fi
	    done
    if [ $a != "0" ];
    then
        b=${a:-1}
        if [ "$b" == "1" ];
        then
                a=$a"1"
        fi
        echo $a
        break
    fi
done
mount $a /media/usb
sudo chmod 777 /media/usb
ID=$(lsusb -tv)
ID=${ID##*"ID "}
nombre=${ID:10}
ID=${ID:0:9}
a=$( sudo mysql $SQL_ARGS "SELECT id_usb FROM usb WHERE id_usb='$ID'";)
b=""
if [[ $a == $b ]]; then
    sudo mysql $SQL_ARGS "INSERT INTO usb (id_usb, nombre, propietrio) VALUES ('$ID', '$nombre', 1);"
    echo "Se ha insertado el registro con ID $ID"
fi 

sudo bash /home/albert/fin/scriptfinal.sh $ID
