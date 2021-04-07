import methods.cluster.cluster
import methods.rules
import methods.diff
import methods.jarm
import methods.cert
import methods.self_signed
import methods.ssh_key
import methods.http.http


methods = {
    "cluster": methods.cluster.cluster,
    "rules": methods.rules,
    "diff": methods.diff,
    "http": methods.http.http,
    "jarm": methods.jarm,
    "cert": methods.cert,
    "self-signed": methods.self_signed,
    "ssh-key": methods.ssh_key,
}
