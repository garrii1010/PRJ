import os
import requests
import subprocess
import mysql.connector
import mysql
import hashlib
import datetime
import pyudev
import json



# Conexión con Servidor
localhost = "http://localhost/"



#Para monit
def writePidFile():
    pid = str(os.getpid())
    currentFile = open("/var/run/pythonscript.pid", "w")
    currentFile.write(pid)
    currentFile.close()
#Para el sha
def get_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()
#Listar el directorio de media/tuusb
def list_files(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            yield os.path.join(root, file)

    
# Conexión con MySQL
try:
    connection = mysql.connector.connect(host='localhost',
                                         database='DBusb',
                                         user='root',
                                         password='contraseña')
    
    comanda="lsblk -S | egrep 'usb' | cut -d' ' -f1 > tmp"
    os.system(comanda)
    for disp in open('tmp','r').readlines():
        disp=disp.rstrip('\n')
        print(f"Searching {disp}")
        comanda2=f"lsblk -o NAME,LABEL | egrep '{disp}1' | rev | cut -d ' ' -f1 | rev > tmp2"
        os.system(comanda2)
        label=open('tmp2','r').readline().rstrip('\n')
        print(f"Media named {label} founded!")
        os.system(f"mkdir /media/{label}")
        os.system(f"mount -t auto /dev/{disp}1 /media/{label}")
        
        try:
            os.system(f"mkdir /var/www/html/archivos/{label}")
            os.system(f"mkdir /var/www/html/archivos/{label}/pos")
            os.system(f"mkdir /var/www/html/archivos/{label}/quar")
            print(f"Folders of {label} created successfully!")
        except FileExistsError:
            print(f"Folders of {label} already exists.")

        # Guardar el Log de ID de USB, y subirlo al apartado de Logs del servidor.
        plantilla =  " <------USB ID------> "
        log_file = open("logusb.txt", "w")
        date = datetime.datetime.now()
        date = datetime.datetime.now()
        log_file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + str(plantilla) + str(label))
        log_file.close()
        requests.post(localhost + 'log/', data=open('logusb.txt', 'rb'))

        # Obtener lista de archivos en el dispositivo
        api_key = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": api_key
        }
        directory = f"/media/{label}"
        for file_path in list_files(directory):
            file_size = os.path.getsize(file_path)
            print(f"The size of the file is {file_size} bytes")
            sha256 = get_sha256(file_path)
            print(f"{sha256} is the SHA256 for this file")
            with open(file_path, "rb") as f:
                if file_size <= 32 * 1024 * 1024:
                # Archivo pequeño usando el request.post normal
                    response = requests.post(url, headers=headers, files={"file": f})
                else:
                # Archivo grande usando request por chunks
                    response = requests.post(url, headers=headers, data=f, stream=True)
                response.raise_for_status()
                json_response = response.json()
                file_id = json_response["data"]["id"]
                print(f"File {file_path} uploaded with ID {file_id}")
                # Obtener file report
                url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                #json_response = response.json()
                data = json.loads(response.content)

            if response.status_code == 200:
                print(f"The analysis for the file {file_path} is completed")
        
                for engine, result in data['data']['attributes']["results"].items():
                    # Si el archivo es "malicious", a tomar por culo
                    if ['category'] == "malicious":
                        categoria = engine + " - " + result["category"]
                        os.remove(file_path)
                    # Si el archivo no es "malicious", sube a quar si hay carpeta llamada "quarentena" y a pos los archivos sin virus. 
                    else:
                        categoria = engine + " - " + result["category"]
                        if 'quarentena' in list_files(directory):
                            route = localhost + f'archivos/quar/' + file_path
                        else:
                            route = localhost + f'archivos/pos/' + file_path
                        requests.post(route, data=open(file_path, 'rb'))
                    # Guardar el Log de archivos, con su Hash y ruta originales y subirlo al apartado de Logs del servidor
                    plantilla =  " <------FILE HASH & ROUTE------> "
                    log_file = open("logfile.txt", "w")
                    date = datetime.datetime.now()
                    log_file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + str(plantilla) + sha256 + ' ' + route + "\n" + categoria + "\n" )
                    log_file.close()
                    requests.post(localhost + 'log/', data=open('logfile.txt', 'rb'))
            else: 
                print(f"The analysis for the file {file_path} is queued, please wait")

            cursorr = connection.cursor()
            sql_select_query = """SELECT id_usb FROM usb ORDER BY id_usb DESC LIMIT 1"""
            cursorr.execute(sql_select_query)
            result = cursorr.fetchone()
            last_id = result[0]
            id_value = int(last_id) + 1
            sql_insert_query = """ INSERT INTO `usb`
                                (`id_usb`, `nombre`) VALUES (%s, %s) """
            insert_tuple = (id_value, label)
            result = cursorr.execute(sql_insert_query, insert_tuple)
            connection.commit()
            """
            while id_value <= 10:
                # Incrementar el valor del ID
                id_value += 1
                # Insertar los valores nuevos
                sql_insert_query = ""INSERT INTO `usb` (`id_usb`, `nombre`) VALUES (%s, %s)""
                insert_tuple = (id_value, label)
                result = cursorr.execute(sql_insert_query, insert_tuple)
                # commit the changes to the database
                connection.commit()
            """
            print("Record inserted successfully into usb table")

            sql_select_query = """SELECT id FROM archivos ORDER BY id DESC LIMIT 1"""
            cursorr.execute(sql_select_query)
            result = cursorr.fetchone()
            last_fileid = result[0]
            id_file = int(last_fileid) + 1
            # Registrar identificador USB (id_usb) y nombre en la tabla de MySQL
            sql_insert_query = """ INSERT INTO `archivos`
                                (`id`, `usb`, `nombre`, `MD5`, `direccion`) VALUES (%s, %s, %s, %s, %s) """
            insert_tuple = (id_file, id_value, file_path, sha256, route)
            result = cursorr.execute(sql_insert_query, insert_tuple)
            connection.commit()

            """
            while id_file <= 10:
                # Incrementar el valor del ID
                id_file += 1
                # Insertar los valores nuevos
                sql_insert_query = "" INSERT INTO `archivos`
                                (`id`, `usb`, `nombre`, `MD5`, `direccion`) VALUES (%s, %s, %s, %s) ""
                insert_tuple = (id_file, id_value, file_path, sha256, route)
                result = cursorr.execute(sql_insert_query, insert_tuple)
                connection.commit()
            """
            print("Record inserted successfully into archivos table")

            writePidFile()

except mysql.connector.Error as e:
    print("Error while connecting to MySQL", e)
finally:
    if (connection.is_connected()):
        #cursorr.close()
        connection.close()
        print("MySQL connection is closed")

