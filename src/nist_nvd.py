# Importo la librerías necesarias
import requests
import json
import os
import pandas as pd
from datetime import datetime, timedelta
import time
from tkinter import Tk,Entry,Button,Canvas,Frame,Label
from tkcalendar import Calendar, DateEntry
import request_cve as cve


# Configuración de ventana
root = Tk()
root.title("NIST NVD")
root.geometry("700x300")
root.resizable(False,False)
root.attributes("-alpha",0.95)


# Frame
frame = Frame(root)
frame.place(relx=0.05,rely=0.1,relheight=0.8,relwidth=0.9)

##### Label ###################################################################
label0 = Label(frame, text="Ingrese los valores para el control")
label0.grid(row=0, column=0)


############################# FECHAS ###########################################


# Calendar
hoy = datetime.today()

label13 = Label(frame, text="From")
label13.grid(row=1, column=0, padx=10, sticky="e")
cal_from = DateEntry(frame, width=10, year=hoy.year, month=hoy.month-1, day=hoy.day)
cal_from.grid(row=1, column=1)
label15 = Label(frame, text="to")
label15.grid(row=1, column=2, padx=10, sticky="w")
cal_to = DateEntry(frame, width=10, year=hoy.year, month=hoy.month, day=hoy.day)
cal_to.grid(row=1, column=3)

def buscar():
    from_ = cal_from.get_date()
    to_ = cal_to.get_date()
    cve.extract(from_, to_)

# Button:Buscar
button_buscar = Button(frame, text="Buscar", command=buscar)
button_buscar.grid(row=3, column=4, padx=5, pady=5,sticky='w')


root.mainloop()
