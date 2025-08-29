# Importo la librerías necesarias
import requests
import json
import os
import pandas as pd
from datetime import datetime, timedelta
import time
from typing import List

def extract(fecha_from, fecha_to):
    '''
    Busco la lista de los CVE por un rango de fecha.
    Armo la tabla con Pandas.
    Filtro según criticidad y tecngolgía

    Args:
        fecha_from (Date): Fecha inicio
        fecha_to (Date): Fecha final

    Returns:
        None
    '''

    # Parámetros 
    url="https://services.nvd.nist.gov/rest/json/cves/2.0/"
    from_time = f"{fecha_from}T00:00:00.000"
    to_time = f"{fecha_to}T23:59:59.999"
    params_index = "startIndex=0"
    params_result_per_page = "resultsPerPage=2000"

    # Realizar la petición
    response_fecha = requests.get(f'{url}?{params_result_per_page}&{params_index}&pubStartDate={from_time}&pubEndDate={to_time}')

    # Json to list:
    list_data = response_fecha.json()

    # Guardo el total de resultados 
    total_result = list_data['totalResults']
    print(f'La cantidad de resultados {total_result} durante {from_time} - {to_time}' )

    # Voy haciendo peticiones cada 2000 resultados
    cve = []
    for i in range(0,total_result,2000):
        # Realizar la petición
        response_fecha = requests.get(f'{url}?{params_index}{i}&pubStartDate={from_time}&pubEndDate={to_time}')
        print(f'Respuesta del servidor: {response_fecha} a partir del indice {i}' )

        # Json to list:
        list_data = response_fecha.json()
        cve = cve + list_data['vulnerabilities']
        


    # Dataframe:
    lista_cve = [ i["cve"] for i in cve ]
    data = pd.DataFrame(lista_cve)

    # Castear las fechas:
    data["published"] = pd.to_datetime(data["published"])
    data["lastModified"] = pd.to_datetime(data["lastModified"])

    cve_cpe_list = []
    severity_cvssv31 = []
    severity_cvssv4 = []
    severity_cvssv2 = []
    cve_description_list = []

    for i in cve:
        # CVE
        cve_id = i['cve']['id']
        
        # CPE
        try:
            cve_cpe = i["cve"]['configurations'][0]['nodes'][0]['cpeMatch'][0]['criteria']
            cve_cpe_list.append(cve_cpe)
        except Exception as e:
            cve_cpe = None
            cve_cpe_list.append(cve_cpe)
        
        # Descripción:
        try:
            cve_description = i["cve"]['descriptions'][1]['value']
            cve_description_list.append(cve_description)
        except Exception as e:
            cve_description = None
            cve_description_list.append(cve_cpe)
        
        # Guardo Severidad para las distintas versiones CVSS
        # versión 3.1
        try:
            severidad =  i["cve"]['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
            severity_cvssv31.append(severidad)
        except Exception as e:
            severity_cvssv31.append(None)
        
        # versión 4.0
        try:
            severidad =  i["cve"]['metrics']['cvssMetricV40'][0]['cvssData']['baseSeverity']
            severity_cvssv4.append(severidad)                      
        except Exception as e:
            severity_cvssv4.append(None)
        
        # versión 2.0
        try:
            severidad =  i["cve"]['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
            severity_cvssv2.append(severidad)
        except Exception as e:
            severity_cvssv2.append(None)



    # Agrego estos datos como columna a la tabla
    data['CPE'] = cve_cpe_list
    data['CVSS_31'] = severity_cvssv31
    data['CVSS_4'] = severity_cvssv4
    data['CVSS_2'] = severity_cvssv2
    data['Description'] = cve_description_list

    marca_modelo = read_inventario()

    cve_high_critical = buscar_en_inventario(data, marca_modelo)

    load(cve_high_critical)



def read_inventario():
    '''
    Leo el inventarios

    Returns:
        DataFrame: Tabla de tecgnologias
    '''
    tecnologias_monex = pd.read_excel(".//data//raw//tecnologias_monex.xlsx")
    marcas_tecno = tecnologias_monex['Marca'].drop_duplicates().values

    return marcas_tecno


def buscar_en_inventario(data_cve, marcas):
    '''
    # Itero entre la lista de marcas y busco en la tabla de los cve del NIST
    
    Args:
        data_cve (Dataframe):
        marcas (Dataframe):

    Returns:
        vuln_high_critical (Dataframe):
    
    '''
    vuln_marcas =[] 
    for i in marcas:
        vuln_df = data_cve[data_cve['CPE'].str.contains(i, case = False, na= False)]
        vuln_marcas.append(vuln_df)
        

    # Concateno la lista de los resultados encontrados
    vuln_marcas = pd.concat(vuln_marcas, ignore_index=True)

    # Filtro por criticidad
    vuln_high_critical = vuln_marcas[vuln_marcas['CVSS_31'].isin(['HIGH','CRITICAL']) |
                                vuln_marcas['CVSS_4'].isin(['HIGH','CRITICAL'])]

    # Extraer el fragmento del CPE (a partir del tercer ":" y del cuarto ":")
    vuln_high_critical['Modelo'] = vuln_high_critical['CPE'].str.split(':').str[4]
    vuln_high_critical['Marca'] = vuln_high_critical['CPE'].str.split(':').str[3]

    # Renombrar columnas para que sean más claras
    vuln_high_critical = vuln_high_critical.rename(columns={
        "published": "Fecha de creación",
        "Description": "Descripción"    
    })

    # Dataframe final
    vuln_high_critical = vuln_high_critical[['id', "Fecha de creación", 'Marca', 'Modelo',
        'Descripción', 'CVSS_31', 'CVSS_4']]
    
    # Ordeno según criticidad
    vuln_high_critical.sort_values(by=['CVSS_31'], inplace=True)

    return vuln_high_critical


def load(listado_cve):
    '''
    # Guardo la info en un archivo CSV

    Args:
        listado_cve (DataFrame):
    '''
    listado_cve.to_csv('.//reports//vuln_high_critical.csv', index=False, encoding='utf-8-sig')



if __name__ == '__main__':
    print(os.getcwd())