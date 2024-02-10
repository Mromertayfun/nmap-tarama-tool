import nmap

def nmap_scan(ip_address, script_vuln=False):
    arguments = '-p 1-1024 -sS -sV -O'
    if script_vuln:
        arguments += ' --script vuln'

    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments=arguments)

    for host in nm.all_hosts():
        print(f'Host: {host}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                print(f'Port: {port}\tService: {service}\tProduct: {product}\tVersion: {version}')

        if script_vuln:
            if 'scripts' in nm[host] and nm[host]['scripts']:
                print('\nZafiyet Taraması Sonuçları:')
                for script_id, script_output in nm[host]['scripts'].items():
                    print(f'Script ID: {script_id}\nOutput: {script_output}\n')
            else:
                print('\nZafiyet Taraması Sonuçları Bulunamadı.')


ip_to_scan = input("Taramak istediğiniz IP adresini girin: ")
script_vuln = input("Zafiyet taraması yapmak istiyor musunuz? (e/h): ").lower() == 'e'

nmap_scan(ip_to_scan, script_vuln)
