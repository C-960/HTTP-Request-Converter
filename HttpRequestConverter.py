from burp import IBurpExtender, IHttpListener, IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json
from request_formatters import FetchRequestFormatter, Python3RequestFormatter  # Import request formatter classes

__version__ = '0.3.0'

# Define the BurpExtender class, implementing the required interfaces
class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    # Register the extension with Burp Suite and set up required listeners
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HTTP Request Converter")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    # Create the context menu items
    def createMenuItems(self, invocation):
        self.context = invocation
        menu_item_fetch = JMenuItem("Convert to Fetch", actionPerformed=self.convert_request(FetchRequestFormatter()))
        menu_item_python3 = JMenuItem("Convert to Python 3", actionPerformed=self.convert_request(Python3RequestFormatter()))
        return [menu_item_fetch, menu_item_python3]
        #menu_item_fetch = JMenuItem("Copy as Fetch", actionPerformed=self.convert_request_to_fetch)
        #return [menu_item_fetch]


    # When the context menu item is clicked, convert the request to a Fetch API call
    def convert_request(self, formatter):
        def inner_convert(event):
            try:
                message_info = self.context.getSelectedMessages()[0]
            except IndexError:
                print("error")
                return

            # Check if it's a request or response
            if self.context.getInvocationContext() not in (IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                                                        IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST):
                return
                
            # Get the HTTP service information and build the full URL
            http_service = message_info.getHttpService()
            protocol = "https" if http_service.getProtocol() == "https" else "http"
            host = http_service.getHost()
            port = http_service.getPort()
            port_suffix = ":{port}".format(port) if (protocol == "http" and port != 80) or (protocol == "https" and port != 443) else ""

            # Get the request and convert it to a Fetch API call
            request = self._helpers.bytesToString(message_info.getRequest())
            #fetch_code = self.convert_to_fetch(request, protocol, host, port_suffix)
            fetch_code = formatter.format_request(request, protocol, host, port_suffix)
            
            # Copy the generated Fetch API call to the clipboard
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            string_selection = StringSelection(fetch_code)
            clipboard.setContents(string_selection, None)
        
        return inner_convert


    # Convert an HTTP request to a JavaScript Fetch API call
    def convert_to_fetch(self, request, protocol, host, port_suffix):
        try:
            # Split the request into headers and body
            http_request = request.split("\r\n\r\n", 1)
            headers_lines, body = http_request[0].split("\r\n", 1), http_request[1]
            
            headers_lines = [x.encode('UTF8') for x in headers_lines]
            request_line, header_lines = headers_lines[0], headers_lines[1:]
            header_lines = header_lines[0].split("\r\n")
            
            # Extract the request method and URL path
            method, url_path, _ = request_line.split(" ")
            full_url = "{protocol}://{host}{port_suffix}{url_path}".format(protocol=protocol, host=host, port_suffix=port_suffix, url_path=url_path)
            full_url = full_url.replace('\'', '\\\'')
            
            
            # Extract the headers from the request
            headers = {}
            for header_line in header_lines:
                header_parts = header_line.split(":")
                print(header_parts)
                header_name = header_parts[0].strip()
                header_value = ':'.join(header_parts[1:]).strip()
                headers[header_name] = header_value

            # Generate the Fetch API call with appropriate headers and body
            fetch_headers = json.dumps(headers, indent=4)
            fetch_body = json.dumps(body)
            
            # Do not include request "body" if method is GET or HEAD
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
        
        except Exception as e:
            print("Error occurred while converting the request to Fetch: {}".format(e))
            fetch_code = "Error: Could not convert the request to Fetch"

        return fetch_code
