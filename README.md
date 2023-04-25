# Copy as Fetch
## What it does
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

## How to install
This extension is not currently in the BApp store.

To install and use the extension:
- Download Jython standalone JAR file from the official website: https://www.jython.org/download
- Install and run Burp Suite.
- Go to the "Extender" tab in Burp Suite, and then click on the "Options" subtab.
- In the "Python Environment" section, locate the Jython standalone JAR file by clicking "Select file..." and choosing the downloaded JAR file.
- Save the Python extension code in a file, for example, Copy-as-Fetch.py.
- In the "Extender" tab, click on the "Extensions" subtab, and then click the "Add" button.
- In the "Add extension" dialog, select "Python" as the "Extension type", click "Select file..." to locate the Copy-as-Fetch.py file, and then click "Next".
- The extension should now be loaded, and you will see "Copy as Fetch" option when you right-click on a request in the HTTP history or any other request viewer/editor.

Inspired by all the other "Copy as..." extensions in the Burp Extension store :grin:
