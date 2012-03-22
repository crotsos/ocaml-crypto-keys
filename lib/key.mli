
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

exception Action_error of string
type action_type = 
    | SIGN
    | TRANSFORM
    | VERIFY
val string_of_action_type : action_type -> string
val action_type_of_strng : string -> action_type

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
}

val process : key_conf -> unit

val ssh_pub_key_of_domain : string -> string list option
val ssh_fingerprint_of_domain: string -> string list option
