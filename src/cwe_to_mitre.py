
import time
import sys
import pandas as pd
sys.path.insert(0,'/usr/lib/chromium-browser/chromedriver')
from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait 
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC

options = webdriver.ChromeOptions() # Usamos chrome, se podria usar otro.
options.add_argument('--headless') # Chromium sin interfaz grafica
options.add_argument('--no-sandbox') # Seguridad
options.add_argument('--disable-dev-shm-usage') # configuracion de linux
options.add_argument('--user-agent=""Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36""') # user agent

# driver = webdriver.Chrome()

# CAPEC

def mapping(links_capec):
    '''
    Buscar si hay patrones de ataques relacionados
    con ID CAPEC

    Arg: lista
    return: lista

    '''

    links_attack = []
    for i in links_capec:
        url_capec = i
        try:
            wd.get(url_capec)

            try:
                # busco si hay patrones de ataques relacionados
                attack_patterns = wd.find_element(By.ID, "Taxonomy_Mappings")
                # En caso de que exista busco los map_attack
                href_attack = attack_patterns.find_elements(By.TAG_NAME,"a")
                # Guardo los links en una lista
                link_aux = []
                for i in href_attack:
                    link_aux.append(i.get_attribute('href'))

                for j in link_aux:
                    # valido url
                    if j.startswith('https://capec.mitre.org'):
                        # Recursividad
                        link_recurs = mapping([j])
                        # print(f'{link_recurs} viene de la recurividad')
                        links_attack.append(link_recurs)
                    elif j.startswith('https://attack.mitre.org/'):
                        links_attack.append(j)
                        # print(f"{j}: Guardo esta refer a mitre")
                    else:
                        # print(f"{j}: No aplica. No guardo nada")
                        pass

            except EC.NoSuchElementException:
                print(f"{url_capec}: No contiene una correlación con mitre")

        except EC.WebDriverException:
            print(f"{url_capec}: No es una url")
    return links_attack

cve = input("Ingresar un CVE:")
# CVE-2025-20122
# CVE-2024-40591
# CVE-2024-24914
# CVE-2025-20210
# CVE-2025-64155
# CVE-2025-59503
# CVE-2026-20045



# Configuramos el web driver
wd = webdriver.Chrome()

# Navegamos la pág NIST con el CVE
url = f"https://nvd.nist.gov/vuln/detail/{cve}"
wd.get(url)

# text_box = wd.find_element(By.ID, "vulnDescriptionTitle")
text_href = wd.find_element(By.XPATH, '//*[@id="vulnTechnicalDetailsDiv"]/table/tbody/tr/td[1]/a')
print(text_href.text)
print(text_href.get_attribute("href"))

# CWE Common Weakness Enumeration
url_cwe = text_href.get_attribute("href")
wd.get(url_cwe)


try:
    #busco si hay patrones de ataques relacionados
    attack_patterns = wd.find_element(By.ID, "Related_Attack_Patterns")

    # En caso de que exista, busco los capec
    href_capec = attack_patterns.find_elements(By.TAG_NAME,"a")

    # Guardo los links en una lista
    links_capec = []
    for i in href_capec:
        links_capec.append(i.get_attribute("href"))

except EC.NoSuchElementException:
    print("No contiene patrones de ataque")
    links_capec = []
    wd.quit()

print(links_capec)

# Llamo a la función mapping para buscar la correlacion con Mitre
links = links_capec
lista_mitre = mapping(links)
print(lista_mitre)

# Guardo el resultado en un txt
with open("./src/map_mitre_detections.txt",'w') as f:
    for i in lista_mitre:
        f.write(f'{i}\n')


wd.quit()
