from dnsrecon import __main__
import dns.resolver

def dns_python(domain):
    """Realiza consultas DNS para diferentes tipos de registros."""
    records = ['A', 'AAAA', 'NS', 'SOA', 'MX', 'TXT', 'CNAME', 'PTR']
    
    for record in records:
        try:
            responses = dns.resolver.resolve(domain, record)
            print("\nRecord response:", record)
            print("-----------------------------------")
            for response in responses:
                print(response)
        except dns.resolver.NoAnswer:
            print(f"Cannot resolve query for record {record}: No answer.")
        except dns.resolver.NXDOMAIN:
            print(f"Cannot resolve query for record {record}: Domain does not exist.")
        except dns.resolver.Timeout:
            print(f"Cannot resolve query for record {record}: Query timed out.")
        except Exception as exception:
            print(f"Error obtaining record {record}: {exception}")

if __name__ == '__main__':
    print('DNS Python:')
    dns_python("www.python.org")
    print('\n-----------------------------------------')
    print('DNSRecon:')
    __main__.main()
    
    