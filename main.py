import re
import time
import prometheus_client
from prometheus_client import Counter, Summary, Gauge
from http.server import BaseHTTPRequestHandler, HTTPServer

# Define Prometheus metrics
request_count = Counter('haproxy_requests_total', 'Total number of requests',
                        ['method', 'endpoint', 'status_code', 'backend'])

request_client_ip = Counter('haproxy_requests_client_ip', 'Total number of requests',
                            ['client_ip', 'backend', 'status_code', 'endpoint'])

request_waiting_time = Gauge('haproxy_request_waiting_time_seconds', 'Request waiting time in ms',
                               ['status_code', 'backend', 'endpoint', 'method'])

request_connect_time = Gauge('haproxy_request_connect_time_seconds', 'Request connect time in ms',
                               ['status_code', 'backend', 'endpoint', 'method'])

request_response_time = Gauge('haproxy_request_response_time_seconds', 'Request response time in ms',
                                ['status_code', 'backend', 'endpoint', 'method'])

request_total_time = Gauge('haproxy_request_total_time_seconds', 'Request total time in ms',
                             ['status_code', 'backend', 'endpoint', 'method'])


# Regex pattern for parsing HAProxy log entries
log_pattern = re.compile(
    r'(?P<client_ip>\S+):(?P<client_port>\d+) \[(?P<timestamp>[^\]]+)\] (?P<frontend>\S+) (?P<backend>[^\/]+)\/(?P<server_name>\S+) (?P<Tq>\d+)\/(?P<Tw>\d+)\/(?P<Tc>\d+)\/(?P<Tr>\d+)\/\+(?P<Tt>\d+) (?P<status_code>\d+) \+\d+ - - --(?P<termination_state>\w{2}) \d+\/\d+\/\d+\/\d+\/\d+ \d+\/\d+ "(?P<method>\S+) (?P<path>[^ ]+) HTTP\/\S+"'
)

log_file_path = "/var/log/haproxy.log"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            output = prometheus_client.generate_latest()
            self.wfile.write(output)
        else:
            self.send_response(404)
            self.end_headers()


def follow(file):
    file.seek(0, 2)  # Go to the end of the file
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.1)  # Sleep briefly
            continue
        yield line


def parse_logs():
    with open(log_file_path, 'r') as log_file:
        log_lines = follow(log_file)
        for line in log_lines:
            match = re.search(log_pattern, line)
            if match:
                data = match.groupdict()
                method = data['method']
                path = data['path']
                status_code = data['status_code']
                backend = data['backend']
                client_ip = data['client_ip']

                try:
                    total_waiting_time = float(data['Tw'])
                    total_connect_time = float(data['Tc'])
                    total_response_time = float(data['Tr'])
                    total_time = float(data['Tt'])

                    # Increment the request count with backend label
                    request_count.labels(method=method, endpoint=path, status_code=status_code, backend=backend).inc()
                    request_client_ip.labels(client_ip=client_ip, status_code=status_code, backend=backend,
                                             endpoint=path).inc()
                    request_waiting_time.labels(status_code=status_code, backend=backend, endpoint=path,
                                                method=method).set(total_waiting_time)
                    request_connect_time.labels(status_code=status_code, backend=backend, endpoint=path,
                                                method=method).set(total_connect_time)
                    request_response_time.labels(status_code=status_code, backend=backend, endpoint=path,
                                                 method=method).set(total_response_time)
                    request_total_time.labels(status_code=status_code, backend=backend, endpoint=path,
                                              method=method).set(total_time)
                except ValueError:
                    # Handle case where conversion to float fails
                    print(f"Error parsing time values in line: {line}")
            else:
                print(f"No match found for line: {line}")


def run_server():
    server_address = ('', 9000)
    httpd = HTTPServer(server_address, MetricsHandler)
    print("Starting server at http://localhost:9000")
    httpd.serve_forever()


if __name__ == "__main__":
    # Start parsing logs in a separate thread or process
    import threading

    log_thread = threading.Thread(target=parse_logs)
    log_thread.start()

    # Start the HTTP server to expose metrics
    run_server()
