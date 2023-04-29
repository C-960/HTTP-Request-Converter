import json

class BaseRequestFormatter:
    def format_request(self, request, protocol, host, port_suffix):
        raise NotImplementedError("Subclasses must implement this method")

class FetchRequestFormatter(BaseRequestFormatter):
    def format_request(self, request, protocol, host, port_suffix):
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
        
        print(fetch_code)
        return fetch_code


class Python3RequestFormatter(BaseRequestFormatter):
    def format_request(self, request, protocol, host, port_suffix):
        # Logic to convert request to Python 3 format
        # ...
        python3_code = "TODO"
        return python3_code
