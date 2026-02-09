import time
import os
import random
import json
import datetime
import glob
import ssl
import hashlib
import socket
import shutil
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
print('Key Checker v1.0')
print('Created By: Anthony R Shively, Ohio USA')
print('')
def ratio(a, b, i=None):
    if a == 0 or b == 0:
        return(0)
    if i == None:
        u = [a, b]
        price = (min(u) / max(u))
        return(price)
    else:
        u = [a, b]
        price = (max(u) / min(u))
        return(price)
def closest_list(number, v, i=None):
    try:
        if i != None:
            a = v.values()
            n = 0
            n_n = 0
            if number not in a:
                for line in a:
                    u = ratio(number, line)
                    if u > n:
                        n = u
                        n_n = line
                number = n_n
            for line in v:
                if float(number) == float(v.get(line)):
                    return(line)
        io = {}
        o = []
        for line in v:
            x = abs(line - number)
            o.append(x)
            io[x] = (line)
        y = min(o)
        return(io.get(y))
    except Exception as e:
        print('Closest List Issues:', e)
def loads(file_name, i=None):
    io = {}
    if i != None:
        if os.path.exists(file_name) == False:
            dumps(file_name, io)
    try:
        if os.path.exists(file_name) == True:
            while True:
                try:
                    with open(file_name, "r") as file:
                        io = json.load(file)
                        break
                except IOError:
                    print("File Waiting:", file_name)
                    time.sleep(1)
    except Exception as e:
        print("Issues with:", file_name, e)
    return (io)
def dumps(file_name, data, i=None):
    if i != None:
        if i == 'Clean':
            if os.path.exists(file_name) == True:
                os.remove(file_name)
        else:
            file_name = os.path.join(i, file_name)
    try:
        if len(data) == 0:
            print('File is empty!:', file_name)
    except:
        pass
    with open(file_name, "w") as config:
        json.dump(data, config, indent=4)
def key_checker():
    try:
        io = {}
        try:
            io_pem = {}
            key_list = glob.glob(os.path.join('*.pem'))
            for line in key_list:
                try:
                    ion = {}
                    with open(line, 'rb') as f:
                        pem_data = f.read()
                    cert = x509.load_pem_x509_certificate(pem_data)
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                    sha_1_o = hashlib.sha1(cert_der).hexdigest().upper()
                    sha_256_o = hashlib.sha256(cert_der).hexdigest().upper()
                    ion['SHA-1'] = (sha_1_o)
                    ion['SHA-256'] = (sha_256_o)
                    time.sleep(.1)
                    with open(line, 'rb') as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                        cn = str(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
                        o = str(cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value)
                        try:
                            valid = str(cert.not_valid_before_utc)
                            ion['Valid'] = (valid)
                        except:
                            pass
                        try:
                            expire = str(cert.not_valid_after_utc)
                            ion['Expire'] = (expire)
                        except:
                            pass
                        try:
                            serial = str(cert.serial_number)
                            ion['Serial'] = (serial)
                        except:
                            pass
                        try:
                            issuer = str(cert.issuer)
                            ion['Issuer'] = (issuer)
                        except:
                            pass
                        try:
                            subject = str(cert.subject)
                            ion['Subject'] = (subject)
                        except:
                            pass
                    v = valid[0:4]
                    e = expire[0:4]
                    name = (v+' - '+e)+' '+cn+' ('+o+').pem'
                    ion['Key Name'] = (name)
                    if os.path.exists(name) == False:
                        shutil.copy(line, name)
                except Exception as e:
                    print('Something wrong with:', line)
                io_pem[line] = (ion)
            io['PEM'] = (io_pem)
        except Exception as e:
            print('Pem Issues:', e)
        try:
            io_crt = {}
            key_list = glob.glob(os.path.join('*.crt'))
            for line in key_list:
                try:
                    ion = {}
                    with open(line, 'rb') as f:
                        crt_data = f.read()
                        if b'-----BEGIN CERTIFICATE-----' in crt_data:
                            cert = x509.load_pem_x509_certificate(crt_data, default_backend())
                        else:
                            cert = x509.load_der_x509_certificate(crt_data, default_backend())
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                    sha_1_o = hashlib.sha1(cert_der).hexdigest().upper()
                    sha_256_o = hashlib.sha256(cert_der).hexdigest().upper()
                    ion['SHA-1'] = (sha_1_o)
                    ion['SHA-256'] = (sha_256_o)
                    time.sleep(.1)
                    with open(line, 'rb') as f:
                        crt_data = f.read()
                        if b'-----BEGIN CERTIFICATE-----' in crt_data:
                            cert = x509.load_pem_x509_certificate(crt_data, default_backend())
                        else:
                            cert = x509.load_der_x509_certificate(crt_data, default_backend())
                        cn = str(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
                        o = str(cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value)
                        try:
                            valid = str(cert.not_valid_before_utc)
                            ion['Valid'] = (valid)
                        except:
                            pass
                        try:
                            expire = str(cert.not_valid_after_utc)
                            ion['Expire'] = (expire)
                        except:
                            pass
                        try:
                            serial = str(cert.serial_number)
                            ion['Serial'] = (serial)
                        except:
                            pass
                        try:
                            issuer = str(cert.issuer)
                            ion['Issuer'] = (issuer)
                        except:
                            pass
                        try:
                            subject = str(cert.subject)
                            ion['Subject'] = (subject)
                        except:
                            pass
                        v = valid[0:4]
                        e = expire[0:4]
                        name = (v + ' - ' + e) + ' ' + cn + ' (' + o + ').crt'
                        ion['Key Name'] = (name)
                        if os.path.exists(name) == False:
                            shutil.copy(line, name)
                except Exception as e:
                    print('Something wrong with:', line)
                io_crt[line] = (ion)
            io['CRT'] = (io_crt)
        except Exception as e:
            print('Crt Issues:', e)
        dumps('key_checker.json', io)
    except Exception as e:
        print('Key Checker Issues:', e)
def main():
    key_checker()
    done = ['Finished', 'Completed', 'Done', 'Successful']
    print(random.choice(done))
    print('Close Program and Open created File: key_checker.json')
    time.sleep(5000)
while True:
    main()