# redirector
>Simple open redirect fuzzer

```bash
$python2 redirect.py --help
usage: redirect.py [-h] [-t <filename>] [-c <cookies>] [-w <URL>]
                   [-X <Method>] [-d <POST_data>]
                   [-H [<header> [<header> ...]]]
                   https://target.com?redirect_url={}

Open Redirect fuzzer v1.0

positional arguments:
  https://target.com?redirect_url={}
                        Enter the address you want to collect, including the protocol, argument.

optional arguments:
  -h, --help            show this help message and exit
  -t <filename>, --txt <filename>
                        Enter the FUZZ list file.
                        Default=fuzz.list
  -c <cookies>, --cookies <cookies>
                        Enter the cookie with session.
                        Ex) "JSESSIONID:AWER; PHPSESSIONID=AAA;"
  -w <URL>, --whitelist <URL>
                        Enter If different whitelist from target.
                        Ex) https://whitelists.com
  -X <Method>, --request <Method>
                        Support Only GET or POST.
                        Default=GET
  -d <POST_data>, --data <POST_data>
                        HTTP POST data.
                        Ex) id=id&pw=pw&redirect_url={}
  -H [<header> [<header> ...]], --headers [<header> [<header> ...]]
                        Pass custom header to server
```
