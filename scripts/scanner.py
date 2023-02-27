import os
import sys
import time
import json
import requests
import datetime

LLAVE_API = "2b6790295ef293069d1767bfa2ab8af0a5a6564e67479237b811fed81e3492fb"

sleepTime = 30

file_route = "C:\Analizar"

URL_API = "https://www.virustotal.com/api/v3/"

def id_log(id,fichero):                                               
    plantilla =  " <------File name------> "
    file = open("log_id.txt", "a")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + id + str(plantilla) + str(fichero) + "\n")
    file.close()
    
def file_analysis_log(file_id, informe):
    plantilla =  " <------File name------> "
    file = open("log_analysis.txt", "a")
    date = datetime.datetime.now()
    file.write("[" + date.strftime("%H") + ":" + date.strftime("%M") + ":" + date.strftime("%S")+ "] " + str(informe) + str(plantilla) + str(file_id))
    print(str(file_id) + str(plantilla) + str(informe))
    file.close()

def read():
    for root, dirs, files in os.walk(file_route, topdown=False):
        for name in files:
            print (name)
            if (os.path.getsize(os.path.join(root, name)) >> 20) > 32:
                id = uploadbiggie(os.path.join(root, name))
            else:
                id = upload(os.path.join(root, name))


def upload(fichero):
    print ("Subir archivo: " + fichero + "...")
    upload_url = URL_API + "files"
    fichero_a_subir = {"file": fichero }
    print("Subir a " + upload_url)
    res = requests.post(upload_url, headers =  {"accept": "application/json", "x-apikey": LLAVE_API}, files = fichero_a_subir)
    if res.status_code == 200:
        result = res.json()
        file_id = result.get("data").get("id")
        print (file_id)
        print ("Archivo subido correctamente: OK")
    else:
        print ("Fallo al subir el archivo :(")
        print ("status code: " + str(res.status_code))
    id_log(file_id,fichero)
    analyse(file_id)
    return file_id

def uploadbiggie(ficherogrande):
        print ("Subir archivo: " + ficherogrande + "...")
        uploadbiggie_url = URL_API + "files/upload_url"
        ficherogrande_a_subir = {"file": ficherogrande }
        print ("Subir a " + uploadbiggie_url)
        res = requests.post(uploadbiggie_url, headers =  {"accept": "application/json", "x-apikey": LLAVE_API}, files = ficherogrande_a_subir)
        if res.status_code == 200:
            result = res.json()
            upload_id = result.get("data")
            print (upload_id)
            print ("Url de subida obtenida correctamente: OK")
        else:
            print ("Fallo al obtener la url de subida el archivo :(")
            print ("status code: " + str(res.status_code))
            time.sleep(sleepTime)
        res = requests.post(upload_id, headers =  {"accept": "application/json", "x-apikey": LLAVE_API}, files = ficherogrande_a_subir)
        if res.status_code == 200:
            result = res.json()
            file_id = result.get("data").get("id")
            print (file_id)
            print ("Archivo subido correctamente: OK")
        else:
            print ("Fallo al subir el archivo :(")   
        id_log()     
        analyse(file_id)
        return file_id
        

def analyse(file_id):
    print ("Obtener informacion de los resultados del analisis...")
    analysis_url = URL_API + "analyses/" + file_id
    res = requests.get(analysis_url, headers =  {"accept": "application/json", "x-apikey": LLAVE_API})
    if res.status_code == 200:
        result = res.json()
        status = result.get("data").get("attributes").get("status")
        if status == "completed":
            informe = ""
            stats = result.get("data").get("attributes").get("stats")
            results = result.get("data").get("attributes").get("results")
            print ("malicious: " + str(stats.get("malicious")))
            print ("undetected : " + str(stats.get("undetected")))
            print ("harmless : " + str(stats.get("harmless")))
            print ()
            for k in results:
                if results[k].get("category") == "malicious":
                    print ("==================================================")
                    print (results[k].get("engine_name"))
                    print ("version : " + results[k].get("engine_version"))
                    print ("category : " + results[k].get("category"))
                    print ("method : " + results[k].get("method"))
                    print ("update : " + results[k].get("engine_update"))
                    print ("==================================================")
                    print ()
                elif results[k].get("category") == "undetected":
                    print ("==================================================")
                    print (results[k].get("engine_name"))
                    print ("version : " + results[k].get("engine_version"))
                    print ("category : " + results[k].get("category"))
                    print ("method : " + results[k].get("method"))
                    print ("update : " + results[k].get("engine_update"))
                    print ("==================================================")
                    print ()

                informe += ("malicious: " + str(stats.get("malicious")))
                informe += ("undetected : " + str(stats.get("undetected")))
                informe += ("harmless : " + str(stats.get("harmless")))

                informe += str(results[k].get("category") == "malicious")
                informe += "==================================================\n"
                informe += results[k].get("engine_name") + "\n"
                informe += "version : " + str(results[k].get("engine_version")) + "\n"
                informe += "category : " + str(results[k].get("category")) + "\n"
                informe += "method : " + str(results[k].get("method")) + "\n"
                informe += "update : " + str(results[k].get("engine_update")) + "\n"
                informe += "==================================================\n"
                
                informe += str(results[k].get("category") == "undetected")
                informe += "==================================================\n"
                informe += results[k].get("engine_name") + "\n"
                informe += "version : " + str(results[k].get("engine_version")) + "\n"
                informe += "category : " + str(results[k].get("category")) + "\n"
                informe += "method : " + str(results[k].get("method")) + "\n"
                informe += "update : " + str(results[k].get("engine_update")) + "\n"
                informe += "==================================================\n"
                
                informe += str(results[k].get("category") == "harmless")
                informe += "==================================================\n"
                informe += results[k].get("engine_name") + "\n"
                informe += "version : " + str(results[k].get("engine_version")) + "\n"
                informe += "category : " + str(results[k].get("category")) + "\n"
                informe += "method : " + str(results[k].get("method")) + "\n"
                informe += "update : " + str(results[k].get("engine_update")) + "\n"
                informe += "==================================================\n"
            
            print ("Analisis satisfactorio: OK")
            file_analysis_log(file_id, informe)
        elif status == "queued":
            print ("status: en cola...")
    else:
        print ("Fallo al obtener los resultados del analisis :(")
        print ("status code: " + str(res.status_code))
        time.sleep(sleepTime)
read()  
