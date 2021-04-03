import modules.http
import modules.ssh
import modules.rdns
import modules.geoip
import modules.unknown
import modules.tls


modules = {
    "rdns": modules.rdns.RdnsModule,
    "geoip": modules.geoip.GeoipModule,
    "http": modules.http.HttpPort,
    "ssh": modules.ssh.SshPort,
    "tls": modules.tls.TlsPort,
    "unknown": modules.unknown.UnknownPort,
}
