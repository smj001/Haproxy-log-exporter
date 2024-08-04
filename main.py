import re
import time
import prometheus_client
from prometheus_client import Counter, Summary
from http.server import BaseHTTPRequestHandler, HTTPServer

# Define Prometheus metrics
request_count = Counter('haproxy_requests_total', 'Total number of requests',
                        ['method', 'endpoint', 'status_code', 'backend', 'client_ip', 'total_waiting_time',
                         'total_connect_time', 'total_response_time', 'total_time'])

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
                # backend = data['backend'] + "/" + data['server_name']
                backend = data['backend']
                client_ip = data['client_ip']
                total_waiting_time = data['Tw']
                total_connect_time = data['Tc']
                total_response_time = data['Tr']
                total_time = data['Tt']

                # Increment the request count with backend label
                request_count.labels(method=method, endpoint=path, status_code=status_code, backend=backend,
                                     client_ip=client_ip, total_waiting_time=total_waiting_time,
                                     total_connect_time=total_connect_time, total_response_time=total_response_time,
                                     total_time=total_time).inc()


def run_server():
    server_address = ('', 9000)
    httpd = HTTPServer(server_address, MetricsHandler)
    print("Starting server at http://localhost:0000")
    httpd.serve_forever()


if __name__ == "__main__":
    # Start parsing logs in a separate thread or process
    import threading

    log_thread = threading.Thread(target=parse_logs)
    log_thread.start()

    # Start the HTTP server to expose metrics
    run_server()
