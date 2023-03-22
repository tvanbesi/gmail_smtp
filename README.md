# gmail_smtp
Simple email sending c program using ssl connection, with gmail smtp server

This was tested only on Windows.

---

You need to fill in the `#define BASE64_LOGIN` and `BASE64_PASSWORD` with your gmail account login and password encoded in base64. You can do this with openssl cli
`echo "login" | openssl base64` and `echo "password" | openssl base64`

You should use a gmail app password if you have 2fa enabled. See [here](https://support.google.com/mail/answer/185833?hl=en).

---

The certificate will expire on Jan 28, 2028. You can find which one you need with the openssl cli:

`openssl s_client -connect smtp.gmail.com:465 -showcerts`

And you can get it from a trusted source on Windows with `certmgr.msc`

---

You need to install openssl. You can get it for Windows [here](https://slproweb.com/products/Win32OpenSSL.html).

---

To compile:

`gcc -Wall -Wextra -Werror main.c -L'C:\Program Files\OpenSSL-Win64\lib' -lssl -lcrypto -I'C:\Program Files\OpenSSL-Win64\include'`

Of course, you need to replace the `-L` and `-I` path according to where you installed openssl.
