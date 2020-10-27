import re 

txt  = """Gastaba dos "parches" oscuros, adheridos a las sienes y que fingían medicamentos. Tenía los ojitos ratoniles, maliciosos. Sabia dilatarlos duramente o “desmayarlos” con recato o levantarlos con disimulo. Caminaba contoneando las “imposibles” caderas y era difícil, al verla, no asociar su estampa achaparrada con la de ciertos palmípedos domésticos. Sortijas celestes y azules le “ahorcaban" las falanges. Tanto el IDS (Intrusion Detection System) como el IPS (Intrusion Prevention System) aumentan la seguridad de las “redes”, vigilando el tráfico, examinando y analizando los paquetes en busca de datos sospechosos. Ambos sistemas basan sus detecciones principalmente en firmas o signaturas ya detectadas y reconocidas como, por ejemplo;
192.168.0.1, 192.168.0.5, 192.168.1.3, 192.168.6.1, 192.168.0.7 entre otros.
Los phonewords o números con "letras" (llamados en inglés: phonewords, vanity numbers), son números de teléfono que aparecen con palabras en lugar de números. De esta manera se memoriza el número más fácilmente. Como consecuencia, las empresas obtienen una mejor respuesta a sus campañas dando una imagen de mejor servicio de atención al cliente. Ejemplos cotidianos de números de teléfono pueden ser 983 145 3235, 997 134 5453, 789 546 1415, 987 154 87 88, 985 134 4344, 555 783 6766
La hora es la Mama, Marrufo, Mferrol indicación del "momento" en que sucede o se hace una cosa en relación con cada una de las veinticuatro partes en que se divide el día, en algunas ocasiones esta 03:00 pm, 04:00 pm, 05:00 pm, 07:00 pm, 05:30 pm, 04:55 pm, 12:00 pm entre otros 
El correo electrónico (también "conocido" como e-mail, un término inglés derivado de electronic mail) es un servicio que permite el intercambio de mensajes a través de sistemas de comunicación electrónicos ubicados: maria@gmail.com, alexispeshoso@gmail.com, russelrenion@gmail.com, eduardo173@gmail.com

Ejemplos de URLs: www.google.com, www.red.com, www.futbolmundial.com, www.stormy.com, www.blackwidow.com, entre otros 
Códigos postales 77121, 98765, 56465, 97543, 67423, 87632
"""

print("--------TODAS LAS PALABRAS QUE TENGAN 7 O MAS LETRAS-------")
funcion= r"[A-Za-záéíóú]{7,}"

palabras = re.findall(funcion,txt)

for acumpalabras in palabras:
    print(acumpalabras)    

print("-----EXPRESIONES QUE NO FINALICEN EN UNA VOCAL----------")
x = r"[A-Za-záéíóú]{1,}[^aeiou\s\W]\b"

xpalabras = re.findall(x,txt)

for xacumulador in xpalabras:
    print(xacumulador)

print("----PALABRAS QUE INICIEN CON M donde la segunda letra no sea vocal----- ")
y = r"[M][^aeiouáéíóú]\w{1,}"

ypalabras = re.findall(y,txt)

for yacumulador in ypalabras:
    print(yacumulador)

print("---------EXPRESIONES ENCERRADAS ENTRE COMILLAS--------")
u= r"(\"[\w\s]+\")"

upalabras = re.findall(u,txt)

for uacumulador in upalabras:
    print(uacumulador)

print("--------------IPS---------------------")
v= r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

vpalabras = re.findall(v,txt)

for vacumulador in vpalabras:
    print(vacumulador)

print("-------LOCALIZAR LAS HORAS-------------")
g= r"[0-9]{1,2}\:[0-9]{1,2}\s[a/p][m]"

gpalabras = re.findall(g,txt)

for gacumulador in gpalabras:
    print(gacumulador)

print("-------buscar telefonos-----------")
te= r"[0-9]{1,3}\s[0-9]{1,3}\s[0-9]{1,4}"

tepalabras = re.findall(te,txt)

for teacumulador in tepalabras:
    print(teacumulador)

print("-------CORREOS ELECTRONICOS-----------")
e= r"\w+[\@]+\w+[.]+\w+"

epalabras = re.findall(e,txt)

for eacumulador in epalabras:
    print(eacumulador)

print("------LOCALIZAR URLs-----------------")
j= r"[Ww]+\w[.]\w+[.]\w+"

jpalabras = re.findall(j,txt)

for jacumulador in jpalabras:
    print(jacumulador)

print("------BUSCAR CODIGO POSTAL----------")
I= r"[0-9]{5}"

Ipalabras = re.findall(I,txt)

for Iacumulador in Ipalabras:
    print(Iacumulador)
