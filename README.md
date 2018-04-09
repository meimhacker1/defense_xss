What is defense.js?

Defense_xss is used to defense xss quickly in the front end of web application,make the attack more difficult.
the encode() use the esapi of OWASP，and the fiter() is user-defined.


How to use?

1.filter()
filter(evil_input)
evil_input is a string, the return value is the filtered string
filter rules:
<, >, ’, ”, /, \


2.encode(),use esapi of OWASP.
2.1 Encoding with encode_HTML() Before Output to html Entity Value.

for example:
 encode_HTML(evil_input)
 Evil_input is a string, the return value is the escaped string
 For example: <body>... Before inserting untrusted data, encode HTML Entity...</body>
 
rule:
& -> &amp;
< –> &lt;
> –> &gt;
" -> &quot;
' –> &#x27;
/ –> &#x2f;

These five characters ',', '.', '-', '_', '' are not encoded.


2.2. Encoding with encode_ATTR() Before Output to html Attribute Value.
 encode_HTMLATTR(evil_input)
 Evil_input is a string, the return value is the escaped string
For example: <div attr=’... Before inserting untrusted data, encode HTML attributes...’></div>

rule:
In addition to Arabic numerals and letters, all other characters are encoded as long as the character's ASCII code is less than 256. The format of the output after encoding is &#xHH; (Beginning with &#x;HH refers to the hexadecimal digit of the character, the semicolon is used as the terminator). The following special symbols are encoded as follows:
& -> &amp;
< –> &lt;
> –> &gt;
" -> &quot;
' –> &#x27;
/ –> &#x2f;
The five characters ',', '.', '-', '_', '' are not encoded.


2.3. Encoding using encode_JS() Before Output to JavaScript.
 encode_JS(evil_input)
 Evil_input is a string, the return value is the escaped string
For example: <script>x = "...encode JavaScript before inserting untrusted data..."</script>

rule:
In addition to Arabic numerals and letters, all other characters are encoded as long as the character's ASCII code is less than 256. The output format after encoding is \xHH (beginning with \x, HH refers to the hexadecimal number corresponding to the character), and the Chinese encoding format is \uHH (starts with \u, HH refers to the unicode corresponding to the character. Hexadecimal number).
The three characters ',', '.', and '_' are not encoded.


2.4 Encoding with encode_ATTR() Before Output to Style attributes
 encode_CSS(evil_input)
 Evil_input is a string, the return value is the escaped string
 For example, <style>selector {property: ...insert untrusted data before CSS encoding...}</style>

rule:
In addition to Arabic numerals and letters, all other characters are encoded as long as the character's ASCII code is less than 256. The format of the encoded output is \HH (preceded by \, HH is the unicode hexadecimal number corresponding to the character).


 2.5 Encoding with encode_URL() Before Output to url params.
 Evil_input is a string, the return value is the escaped string
 For example: <a href="http://www.abcd.com?param=...URL encoding before inserting untrusted data...">Link Content</a>

rule:
In addition to Arabic numerals and letters, all other characters are encoded as long as the character's ASCII code is less than 256. The output format after encoding is %HH (starting with %, HH refers to the hexadecimal number corresponding to the character), the encoding format of the Chinese character is %uHH (starting with %u, HH refers to the unicode of the character. Hexadecimal number).
For @ * _ + - ./ these 7 characters are not processed.

Just see the DEMO!