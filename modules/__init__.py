import modules.http
import modules.ssh
import modules.rdns
import modules.unknown
import modules.tls

modules = {
    "http": modules.http.HttpPort,
    "ssh": modules.ssh.SshPort,
#    "rdns": modules.rdns.RdnsModule,
    "unknown": modules.unknown.UnknownPort,
    "tls": modules.tls.TlsPort,
}
