import socket
import ssl
import requests
import threading
import queue
import re

q = queue.Queue()


WEB_PORTS = {
    80: "http",
    443: "https",
    8080: "http",
    8000: "http",
    8443: "https"
}

cpe_map = {
    "apache": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "iis": ("microsoft", "iis"),
    "cloudflare": ("cloudflare", "cloudflare")
}


def get_server_info(server):

    server = server.lower()

    if "apache" in server:

        match = re.search(r"apache/?([0-9.]*)", server)

        version = match.group(1) if match else ""

        return "apache", version

    elif "nginx" in server:

        match = re.search(r"nginx/?([0-9.]*)", server)

        version = match.group(1) if match else ""

        return "nginx", version

    elif "iis" in server:

        match = re.search(r"iis/?([0-9.]*)", server)

        version = match.group(1) if match else ""

        return "iis", version

    elif "cloudflare" in server:

        return "cloudflare", ""

    return "unknown", ""


def grab_banner(host, port):

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(5)

        s.connect((host, port))

        # HTTPS
        if WEB_PORTS[port] == "https":

            context = ssl.create_default_context()

            s = context.wrap_socket(
                s,
                server_hostname=host
            )

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )

        s.send(request.encode())

        data = b""

        while True:

            try:

                part = s.recv(4096)

                if not part:
                    break

                data += part

            except:
                break

        s.close()

        return data.decode(errors="ignore")

    except:
        return None


def parse_server(response):

    if not response:
        return "unknown", ""

    # Try server header
    match = re.search(
        r"server:\s*(.+)",
        response,
        re.IGNORECASE
    )

    if match:

        server = match.group(1)

        return get_server_info(server)

    # Fallback detection
    lower = response.lower()

    if "nginx" in lower:
        return "nginx", ""

    elif "apache" in lower:
        return "apache", ""

    elif "iis" in lower:
        return "iis", ""

    elif "cloudflare" in lower:
        return "cloudflare", ""

    return "unknown", ""

def get_cves(vendor, product, version):

    try:

        if version != "":

            cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

        else:

            cpe = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"

        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?cpeName={cpe}"
        )

        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        if response.status_code != 200:
            return []

        data = response.json()

        return data.get("vulnerabilities", [])

    except:
        return []

def scan(host, port):

    print(f"\nChecking port {port}...")

    response = grab_banner(host, port)

    if not response:

        print("No response.")

        return

    print("Possible web server found.")

    product, version = parse_server(response)

    print("Server:", product)

    if product == "unknown":

        print("Could not identify server type.")
        print("-" * 60)

        return

    print("Version:", version)

    vendor, service = cpe_map[product]

    vulns = get_cves(vendor, service, version)

    if len(vulns) == 0:

        print("No CVEs found.")

    else:

        print(f"Found {len(vulns)} CVEs")

        for v in vulns[:5]:

            cve = v["cve"]

            print("\nID:", cve.get("id"))

            try:

                score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]

                print("CVSS:", score)

            except:

                print("CVSS: N/A")

            try:

                desc = cve["descriptions"][0]["value"]

                print("Description:", desc[:200])

            except:

                print("No description")

            print("-" * 60)


def worker(host):

    while True:

        try:

            port = q.get(False)

        except:
            break

        try:

            if port in WEB_PORTS:

                scan(host, port)

        except:
            pass

        q.task_done()



host = input("Enter target: ")

start_port = int(input("Enter start port: "))

end_port = int(input("Enter end port: "))



for port in range(start_port, end_port + 1):

    q.put(port)


threads = []

for i in range(20):

    t = threading.Thread(
        target=worker,
        args=(host,)
    )

    t.start()

    threads.append(t)

q.join()

print("\nFinished scanning.")