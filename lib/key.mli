
exception Key_error of string
type key_type = 
    | PEM_PUB
    | PEM_PRIV
    | PEM_CERT
    | DNS_PUB
    | DNS_PRIV
    | SSH_PUB
val string_of_key_type : key_type -> string
val key_type_of_string : string -> key_type
val keys : (string * key_type) list

exception Action_error of string
type action_type = 
    | SIGN
    | TRANSFORM
    | VERIFY
val string_of_action_type : action_type -> string
val action_type_of_strng : string -> action_type
val actions : (string * action_type) list

type key_conf = {
    mutable in_key: string;
    mutable in_issuer: string;
    mutable in_ca_priv: string;
    mutable in_type: key_type;
    mutable action : action_type;
    mutable cert_subj : string;
    mutable out_key : string;
    mutable out_type : key_type;
    mutable duration : int;
    mutable ns_ip : string;
    mutable ns_port : int;
}

val process : key_conf -> unit Lwt.t
val string_of_process : key_conf -> string Lwt.t

val create_rsa_key : string -> int -> Cryptokit.RSA.key 
val load_rsa_priv_key : string -> Cryptokit.RSA.key

val ssh_fingerprint_of_domain: ?server:string -> ?port:int -> string -> 
        string list option Lwt.t
val ssh_pub_key_of_domain : ?server:string -> ?port:int ->string -> 
        string list option Lwt.t
val dnskey_of_pem_pub_file : string -> string list option Lwt.t
val dnskey_rdata_of_pem_pub_file : string -> int -> Dns.Packet.dnssec_alg -> 
  Dns.Packet.rdata option Lwt.t
val dnskey_rdata_of_pem_priv_file : string -> int -> Dns.Packet.dnssec_alg -> 
  Dns.Packet.rdata option Lwt.t
val dnskey_of_pem_priv_file : string -> string list option Lwt.t
