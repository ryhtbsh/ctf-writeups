```
$ curl https://beep-boop.ctf.ritsec.club/robots.txt
User-agent: *
Disallow: /  # Disallow all robots from indexing any content

UlN7ZzMwbTJ0eV9kQHNoXyFzX2whZjN9
$ echo -n UlN7ZzMwbTJ0eV9kQHNoXyFzX2whZjN9 | base64 -d
```
