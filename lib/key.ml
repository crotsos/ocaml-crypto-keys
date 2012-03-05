open Rsa

exception Key_error of string
type key_type = 
    | PEM_PUB
    | PEM_PRIV
    | PEM_CERT
    | DNS_PUB
    | DNS_PRIV
let string_of_key_type = function
    | PEM_PUB -> "PEM_PUB" 
    | PEM_PRIV-> "PEM_PRIV"
    | PEM_CERT-> "PEM_CERT"
    | DNS_PUB -> "DNS_PUB"
    | DNS_PRIV-> "DNS_PRIV" 
let key_type_of_string = function
    |  "PEM_PUB" ->PEM_PUB 
    |  "PEM_PRIV"->PEM_PRIV
    |  "PEM_CERT"->PEM_CERT
    |  "DNS_PUB" ->DNS_PUB 
    |  "DNS_PRIV"->DNS_PRIV
    | a -> raise(Key_error(Printf.sprintf "error key type %s" a))


exception Action_error of string
type action_type = 
    | SIGN
    | TRANSFORM
    | VERIFY
let string_of_action_type = function
    | SIGN     -> "SIGN" 
    | TRANSFORM-> "TRANSFORM"
    | VERIFY   -> "VERIFY"
let action_type_of_string = function
    | "SIGN"     ->  SIGN      
    | "TRANSFORM"->  TRANSFORM
    | "VERIFY"   ->  VERIFY   
    | a -> raise (Action_error (Printf.sprintf "error action: %s" a))

type key_conf = {
    mutable in_key: string;
    mutable in_ca_cert: string;
    mutable in_ca_priv: string;
    mutable in_type: key_type;
    mutable action : action_type;
    mutable cert_subj : string;
    mutable out_key : string;
    mutable out_type : key_type;
}

let load_key file typ = 
    Printf.printf "loading key %s (%s)" file (string_of_key_type typ);
    match typ with 
    | PEM_PRIV -> 
            let key = Rsa.read_rsa_privkey file in 
            print_rsa_key key

let convert_key conf =
    Printf.printf "converting key types...\n";
    let key = load_key conf.in_key conf.in_type in 
    ()



let process conf = 
    Printf.printf "processing keys...\n%!";
    match conf.action with 
    | TRANSFORM -> convert_key conf
    | _ -> Printf.printf "Unsupported action %s" (string_of_action_type
    conf.action)


