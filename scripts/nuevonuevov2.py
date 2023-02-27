import os
import requests
import mysql.connector
from mysql.connector import Error
import hashlib
import datetime

# Conexión con VT
api_key = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"
url = 'https://www.virustotal.com/api/v3/files'
headers = {'x-apikey': api_key}

# Conexión con Servidor
localhost = 'http://localhost/'

# Conexión con MySQL
try:
    connection = mysql.connector.connect(host='localhost',
                                         database='DBusb',
                                         user='DBgod',
                                         password='dbGOD')

    # Scan del USB
    for root, dirs, files in os.walk("/media/usb"):
        for file in files:
            # Envío a VT de los archivos del mismo
            params = {'hash': hashlib.sha256(open(file, 'rb').read()).hexdigest()}
            response = requests.get(url, params=params, headers=headers)
            data = response.json()

            # Si el archivo es "malicious", a tomar por culo
            if data['data']['attributes']['last_analysis_results']['malicious'] == True:
                os.remove(file)

            # Si el archivo no es "malicious", sube a quar si hay carpeta llamada "quarentena" y a pos los archivos sin virus. 
            else:
                if 'quarentena' in root:
                    route = localhost + 'archivos/quar/' + file
                else:
                    route = localhost + 'archivos/pos/' + file
                requests.post(route, data=open(file, 'rb'))

            # Registrar identificador USB (id_usb) y nombre en la tabla de MySQL
            cursor = connection.cursor()
            sql_insert_query = """ INSERT INTO `archivos`
                                  (`usb_id`, `nombre`) VALUES (%s, %s) """
            insert_tuple = (usb_id, file)
            result = cursor.execute(sql_insert_query, insert_tuple)
            connection.commit()
            print("Record inserted successfully into archives table")

except Error as e:
    print("Error while connecting to MySQL", e)
finally:
    if (connection.is_connected()):
        cursor.close()
        connection.close()
        print("MySQL connection is closed")

# Guardar el Log de archivos, con su Hash y ruta originales y subirlo al apartado de Logs del servidor
plantilla =  " <------FILE HASH & ROUTE------> "
log_file = open("logfile.txt", "w")
date = datetime.datetime.now()
log_file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + str(plantilla) + data['data']['attributes']['last_analysis_results']['hash'] + ' ' + route)
log_file.close()
requests.post(localhost + 'log/', data=open('logfile.txt', 'rb'))

# Guardar el Log de ID de USB, y subirlo al apartado de Logs del servidor.
plantilla =  " <------USB ID------> "
log_file = open("logusb.txt", "w")
date = datetime.datetime.now()
date = datetime.datetime.now()
file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + str(plantilla) + str(usb_id))
log_file.close()
requests.post(localhost + 'log/', data=open('logusb.txt', 'rb'))