import os
import pkgutil
from subprocess import Popen, PIPE

__path__ = pkgutil.extend_path(__path__, __name__)

def install_signing_policy(signing_policy, cadir, ca_hash):
    """
    Installs a signing policy file with the given hash to the trusted ca
    directory.
    """
    if signing_policy is None:
        raise Exception("Invalid signing_policy parameter")

    if cadir is None:
        raise Exception("Invalid cadir parameter")

    if os.path.exists(signing_policy):
        ca_signing_policy_file = file(signing_policy, "r")
        try:
            signing_policy = ca_signing_policy_file.read()
        finally:
            ca_signing_policy_file.close()

    try:
        old_umask = os.umask(0133)

        go_ca_signing_file = open(
                os.path.join(cadir, ca_hash+".signing_policy"), "w")
        try:
            go_ca_signing_file.write(signing_policy)
        finally:
            go_ca_signing_file.close()
    finally:
        os.umask(old_umask)

def install_ca_cert(cert, cadir, ca_hash=None):
    """
    Installs a ca certificate file into the trusted ca
    directory. If ca_hash is not none, then it is used, otherwise,
    we determine it from the cert itself. The cert can be either a 
    path to a file name or the certificate data
    """
    if cert is None:
        raise Exception("Invalid cert parameter")
    if cadir is None:
        raise Exception("Invalid cadir parameter")

    if os.path.exists(cert):
        ca_cert_file = file(ca_cert, "r")
        try:
            cert = ca_cert_file.read()
        finally:
            ca_cert_file.close()

    if ca_hash is not None:
        ca_hash = get_certificate_hash_from_data(cert)

    try:
        old_umask = os.umask(0133)

        go_ca_certfile = open(os.path.join(cadir, ca_hash+'.0'), "w")
        try:
            go_ca_certfile.write(cert)
        finally:
            go_ca_certfile.close()
    finally:
        os.umask(old_umask)

def install_ca(cadir, ca_cert=None, ca_signing_policy=None, ca_hash=None):
    """
    Installs a CA certificate and signging policy into cadir.
    The ca_cert and ca_signing_policy parameters can be either paths to
    the files containing the data or the data itself.  If the ca_hash is not
    specified, it is determined from the certificate data.  If the certificate
    and policy aren't specified, the default go-ca-cert is from the package is
    used.
    """
    if cadir == None:
        raise Exception("Invalid cadir parameter")

    if ca_cert is not None and os.path.exists(ca_cert):
        ca_cert_file = file(ca_cert, "r")
        try:
            ca_cert = ca_cert_file.read()
        finally:
            ca_cert_file.close()
    if ca_signing_policy is not None and os.path.exists(ca_signing_policy):
        ca_signing_policy_file = file(ca_signing_policy, "r")
        try:
            ca_signing_policy = ca_signing_policy_file.read()
        finally:
            ca_signing_policy_file.close()

    if ca_cert is None:
        ca_cert = pkgutil.get_data("globus.connect.security", "go-ca-cert.pem")
    if ca_signing_policy is None:
        ca_signing_policy = pkgutil.get_data(
                "globus.connect.security", "go-ca-cert.signing_policy")

    if ca_hash is None:
        ca_hash = get_certificate_hash_from_data(ca_cert)

    install_ca_cert(ca_cert, cadir, ca_hash)
    install_signing_policy(ca_signing_policy, cadir, ca_hash)

def get_certificate_subject(cert_file_path, nameopt=''):
    """
    Parse the X.509 certificate located at cert_file_path and return
    a string containing the Subject DN of the certificate
    """
    args = [ 'openssl', 'x509', '-subject', '-in', cert_file_path, '-noout' ]
    if nameopt != '':
        args.append('-nameopt')
        args.append(nameopt)
    proc = Popen(args, stdout = PIPE, stderr = PIPE)
    (out, err) = proc.communicate()
    returncode = proc.returncode

    if returncode != 0:
        raise Exception("Error " + str(returncode) +
            " getting certificate subject from " +
            cert_file_path + "\n" + err)
    subject = out[9:].strip()

    return subject

def get_certificate_hash(cert_file_path):
    args = [ 'openssl', 'x509', '-hash', '-in', cert_file_path, '-noout' ]
    proc = Popen(args, stdout = PIPE, stderr = PIPE)
    (out, err) = proc.communicate()
    returncode = proc.returncode

    if returncode != 0:
        raise Exception("Error " + str(returncode) +
            " getting certificate subject from " +
            cert_file_path + "\n" + err)
    hashval = out.strip()

    return hashval

def get_certificate_hash_from_data(cert_data):
    args = [ 'openssl', 'x509', '-hash', '-noout' ]
    proc = Popen(args, stdin = PIPE, stdout = PIPE, stderr = PIPE)
    (out, err) = proc.communicate(cert_data)
    returncode = proc.returncode

    if returncode != 0:
        raise Exception("Error " + str(returncode) +
            " getting certificate subject from " +
            cert_data + "\n" + err)
    hashval = out.strip()

    return hashval

def openssl_version():
    args = ['openssl', 'version']
    proc = Popen(args, stdin=None, stdout=PIPE, stderr=None)
    (out,err) = proc.communicate()
    version = out.split()[1]
    return int(version.split(".")[0])
    

