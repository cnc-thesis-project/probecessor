import methods.cluster.cluster
import methods.port_cluster.cluster
import methods.diff
import methods.jarm
import methods.cert
import methods.self_signed
import methods.ssh_key


methods = {
    "cluster": methods.cluster.cluster,
    "port-cluster": methods.port_cluster.cluster,
    "diff": methods.diff,
    "jarm": methods.jarm,
    "cert": methods.cert,
    "self-signed": methods.self_signed,
    "ssh-key": methods.ssh_key,
}
