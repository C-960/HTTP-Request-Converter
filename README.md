# Copy as Fetch
Burp Suite extension that adds a menu entry to convert a request to a JavaScript fetch request and copy it to the clipboard:

![image](https://user-images.githubusercontent.com/16190664/234110234-a30ea0ee-4c23-4aec-bd48-960423a32e3f.png)

The result is a JavaScript request using the fetch API, which can be used in code or straight in the developer console for debugging etc.:

```javascript
fetch('http://example.com/', {
                method: 'GET',
                headers: {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", 
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36", 
    "Connection": "close", 
    "Host": "example.com", 
    "Accept-Encoding": "gzip, deflate", 
    "Upgrade-Insecure-Requests": "1", 
    "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
},
            })
            .then(response => response.text())
            .then(data => console.log(data))
            .catch(error => console.error('Error:', error));
```
