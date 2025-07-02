ui = true
disable_mlock = true

storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8202"
  tls_disable = 1
}

api_addr = "http://0.0.0.0:8202"
cluster_addr = "https://0.0.0.0:8201"
