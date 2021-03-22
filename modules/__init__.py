import modules.http
import modules.ssh
import modules.rdns
import modules.geoip
import modules.unknown
import modules.tls

modules = {
    "http": modules.http.HttpPort,
    "ssh": modules.ssh.SshPort,
    "rdns": modules.rdns.RdnsModule,
    "geoip": modules.geoip.GeoipModule,
    "unknown": modules.unknown.UnknownPort,
    "tls": modules.tls.TlsPort,
}
