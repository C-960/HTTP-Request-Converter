from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Copy as Fetch")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        self.context = invocation
        menu_item_fetch = JMenuItem("Copy as Fetch", actionPerformed=self.convert_request_to_fetch)
        return [menu_item_fetch]
        
    def convert_request_to_fetch(self, event):
        message_info = self.context.getSelectedMessages()[0]

        # Check if it's a request or response
        if self.context.getInvocationContext() not in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                                                       IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST):
            return

        http_service = message_info.getHttpService()
        protocol = "https" if http_service.getProtocol() == "https" else "http"
        host = http_service.getHost()
        port = http_service.getPort()
        port_suffix = ":{port}".format(port) if (protocol == "http" and port != 80) or (protocol == "https" and port != 443) else ""

        request = self._helpers.bytesToString(message_info.getRequest())
        fetch_code = self.convert_to_fetch(request, protocol, host, port_suffix)
        #print(fetch_code)
        
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        string_selection = StringSelection(fetch_code)
        clipboard.setContents(string_selection, None)


    def convert_to_fetch(self, request, protocol, host, port_suffix):
   
        http_request = request.split("\r\n\r\n", 1)
        headers_lines, body = http_request[0].split("\r\n", 1), http_request[1]
        
        headers_lines = [x.encode('UTF8') for x in headers_lines]
        request_line, header_lines = headers_lines[0], headers_lines[1:]
        header_lines = header_lines[0].split("\r\n")
        
        method, url_path, _ = request_line.split(" ")
        full_url = "{protocol}://{host}{port_suffix}{url_path}".format(protocol=protocol, host=host, port_suffix=port_suffix, url_path=url_path)
        full_url = full_url.replace('\'', '\\\'')
        
        headers = {}
        for header_line in header_lines:
            header_parts = header_line.split(":")
            print(header_parts)
            header_name = header_parts[0].strip()
            header_value = ':'.join(header_parts[1:]).strip()
            headers[header_name] = header_value

        fetch_headers = json.dumps(headers, indent=4)
        fetch_body = json.dumps(body)
        
        if method == "GET" or method == "HEAD":
            fetch_code = """fetch('{url}', {{
                method: '{method}',
                headers: {fetch_headers},
            }})
            .then(response => response.text())
            .then(data => console.log(data))
            .catch(error => console.error('Error:', error));
            """.format(url=full_url, method=method, fetch_headers=fetch_headers)
        else:
            fetch_code = """fetch('{url}', {{
                method: '{method}',
                headers: {fetch_headers},
                body: {fetch_body}
            }})
            .then(response => response.text())
            .then(data => console.log(data))
            .catch(error => console.error('Error:', error));
            """.format(url=url, method=method, fetch_headers=fetch_headers, fetch_body=fetch_body)

        return fetch_code